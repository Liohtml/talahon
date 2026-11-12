# Model Provider: vLLM or Anthropic

Talahon's agent loop speaks the OpenAI-compatible chat API to the **host LLM
gateway**. What the gateway talks to is the provider:

| `TALAHON_PROVIDER` | upstream | notes |
|---|---|---|
| `vllm` (default) | your vLLM server | passthrough, see below |
| `anthropic` | Anthropic Messages API | translated in the gateway, see [Anthropic](#anthropic) |


Talahon runs its agents against a **vLLM** server through vLLM's
OpenAI-compatible API (`/v1/chat/completions` with tool calling and
structured outputs). The agent loop is native Rust (`crates/talon-agent`),
so any model vLLM can serve with a working tool-call parser can drive an
investigation.

## TL;DR

```bash
# /opt/talahon/.env
TALAHON_VLLM_BASE_URL=http://vllm.internal:8000
TALAHON_VLLM_MODEL=Qwen/Qwen3-32B
TALAHON_VLLM_FAST_MODEL=Qwen/Qwen3-8B        # optional: compaction / extraction
TALAHON_VLLM_MAX_CONTEXT=131072              # model context window (tokens)
TALAHON_VLLM_API_KEY=...                     # only if vLLM runs with --api-key
```

Restart Talahon. Every group inherits the provider; per-group overrides live in
the group's `containerConfig.vllm` (see `crates/talon-core/src/types.rs`).

## Starting vLLM

Tool calling must be enabled server-side, with the parser matching the model
family:

```bash
vllm serve Qwen/Qwen3-32B \
  --served-model-name Qwen/Qwen3-32B \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --reasoning-parser qwen3 \
  --enable-prefix-caching \
  --max-model-len 131072 \
  --api-key "$VLLM_API_KEY"
```

| Model family | `--tool-call-parser` | Notes |
|---|---|---|
| Qwen2.5 / Qwen3 (instruct) | `hermes` | Qwen3: add `--reasoning-parser qwen3`; `TALAHON_VLLM_ENABLE_THINKING` toggles thinking |
| Llama 3.1 / 3.3 | `llama3_json` | 70B recommended for full investigations |
| Mistral / Mistral-Small | `mistral` | |
| DeepSeek-V3 / R1 distills | `deepseek_v3` / `hermes` | |

If a model or server emits tool calls as plain text anyway (Hermes
`<tool_call>`, Mistral `[TOOL_CALLS]`, Llama `<|python_tag|>`, fenced JSON),
`talon-llm` recovers them client-side and only accepts tools that were
actually offered.

**Prefix caching matters.** Talahon keeps the system prompt byte-stable across
turns (volatile data such as the current time goes into the first user
message), so `--enable-prefix-caching` turns most of each turn's prompt into
cache hits. Cache hits are reported back to the host as
`cache_read_input_tokens`.

## How requests flow

```
talahon-agent (container) ──Bearer <per-run token>──▶ talahon LLM gateway (host) ──Bearer <vLLM key>──▶ vLLM
```

The host starts an LLM gateway (`crates/talon-llm`, default
`TALAHON_LLM_GATEWAY_PORT=3001`, bound to the docker bridge address on Linux).
For every container run it issues a short-lived token and passes the
endpoint to the container **over stdin** — never in environment variables, so
it is invisible to `docker inspect` and to tool subprocesses. The gateway:

- validates the per-run token (stored only as a SHA-256 digest; revoked when
  the run ends),
- injects the real vLLM API key, which never enters a container,
- pins the model to the configured allow-list (unknown model -> default),
- clamps `max_tokens`, forces `n = 1`, strips server-side knobs such as
  `chat_template`, `logits_processors`, `best_of`, `vllm_xargs`,
- rate-limits and concurrency-limits per token, caps the requests in flight
  overall and per lane (see [Capacity between lanes](#capacity-between-lanes)),
  caps body size,
- counts usage per group and audits authentication failures.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `TALAHON_VLLM_BASE_URL` | — | vLLM server URL (required) |
| `TALAHON_VLLM_MODEL` | — | served model name (required) |
| `TALAHON_VLLM_FAST_MODEL` | `MODEL` | auxiliary model for compaction / summarisation |
| `TALAHON_VLLM_MAX_CONTEXT` | 32768 | context window; drives compaction (~75 %) |
| `TALAHON_VLLM_MAX_OUTPUT` | — | max output tokens per completion |
| `TALAHON_VLLM_TEMPERATURE`, `TALAHON_VLLM_TOP_P` | server default | sampling |
| `TALAHON_VLLM_ENABLE_THINKING` | — | `chat_template_kwargs.enable_thinking` |
| `TALAHON_VLLM_TIMEOUT_SECS` | — | per-request timeout |
| `TALAHON_VLLM_API_KEY` | — | secret; read from `.env` only, held by the gateway |
| `TALAHON_LLM_GATEWAY_PORT` | 3001 | gateway port |
| `TALAHON_LLM_GATEWAY_BIND` | auto | override the auto-detected bind address |
| `TALAHON_LLM_GATEWAY_RPM` | 120 | requests per minute per run token (`0` disables) |
| `TALAHON_LLM_GATEWAY_MAX_CONCURRENT` | 32 | requests in flight across all runs, streams until they end; excess gets `503` + `Retry-After` (`0` disables) |
| `TALAHON_LLM_GATEWAY_LANE_SHARE` | 75 | percent of `MAX_CONCURRENT` one lane may hold at a time; excess gets `429` + `Retry-After` (`0` or `100` disables) |
| `TALAHON_BLOCKED_HOSTS` | — | hosts routed to 127.0.0.1 in every container |

`TALAHON_PROVIDER` values other than `vllm` are ignored with a warning, and
stored group configs that name another provider fall back to the `.env` vLLM
defaults.

## Capacity between lanes

Every run has its own gateway token (at most 8 requests in flight, 120 per
minute), and the gateway serves at most `TALAHON_LLM_GATEWAY_MAX_CONCURRENT`
requests at a time. On their own these limits would let one lane — several
runs sharing a lane key, an alert flood for one customer, or a compromised
agent in a tight loop — hold every slot while interactive analysts and the
investigation lane get `503`.

The gateway therefore counts the requests in flight per **lane** (the token
label, which is the lane's IPC key; all tokens of the lane count together)
and limits one lane to a share of the global cap:

```
lane limit C = max(1, floor(MAX_CONCURRENT x LANE_SHARE / 100))     default: 24 of 32
```

- A request from a lane that already holds `C` slots is refused with `429`,
  `Retry-After: 1` and `"reason": "lane_share_exceeded"` in the error body.
  Nothing is queued; the agent's client retries with backoff.
- Below its limit a lane uses free capacity like before; `503` still means
  that all `MAX_CONCURRENT` slots are taken.
- **Guarantee:** `k` other lanes together hold at most `k x C` slots, so a
  lane is never refused for capacity while it holds fewer than
  `MAX_CONCURRENT - k x C` slots. With the defaults one lane alone can never
  take the last 8 slots — one run's worth — from the others. To be protected
  against several saturating lanes at once, lower the share: with
  `TALAHON_LLM_GATEWAY_LANE_SHARE=25` every lane keeps 8 slots against up to
  three saturating lanes.
- **Not covered:** more saturating lanes than the share allows for (with the
  default, two lanes at their limit of 24 can fill all 32 slots); fairness of
  tokens per second on the model server (a slot is a request, whatever its
  size); and requests admitted before the limit applied (see the next point),
  which finish normally.
- The limit applies once the gateway has issued tokens for a second lane. A
  deployment with a single lane keeps the whole cap, exactly as before. The
  limit is also off when `MAX_CONCURRENT` is `0` or `1`, and with a share of
  `0` or `100`.

Operators see throttled lanes in the audit log (`gateway.request`, outcome
`denied`, actor = lane, `reason: lane_share_exceeded` with `lane_in_flight`
and `lane_limit`; rate-limited like all gateway denials), in the gateway's
debug log, and in the gateway statistics (`lane_limited` overall and per
label, `in_flight_by_lane`).

## Model selection

Practical floor for the full SOC investigation flow (10 MCP servers, 100+
tools, multi-step reasoning) is a strong ~30B instruct model; 70B-class or
large MoE models give the most reliable tool discipline. Pair a large primary
model with a small `TALAHON_VLLM_FAST_MODEL` for compaction to keep long
sessions cheap.

## Verifying

```bash
talahon setup vllm      # probes <base>/v1/models, checks MODEL and FAST_MODEL are served
talahon doctor          # environment + container + gateway + vLLM in one report
```

## Anthropic

```bash
# /opt/talahon/.env
TALAHON_PROVIDER=anthropic
TALAHON_ANTHROPIC_MODEL=claude-sonnet-5-5
TALAHON_ANTHROPIC_FAST_MODEL=claude-haiku-5-5   # optional
TALAHON_ANTHROPIC_MAX_CONTEXT=200000
TALAHON_ANTHROPIC_API_KEY=...                   # host only, like TALAHON_VLLM_API_KEY
```

Then `talahon setup vllm` (probes `GET /v1/models` with the key) and
`talahon doctor` as usual. Nothing changes inside the container: the agent
keeps calling `/v1/chat/completions` on the gateway with its per-run token,
and the gateway translates (`crates/talon-llm/src/anthropic/`):

| OpenAI chat field | Messages API |
|---|---|
| `system` messages | `system` text blocks, one `cache_control: ephemeral` breakpoint (Talahon's system prompt is byte-stable, so every turn after the first is a cache hit) |
| `user` / `assistant` / `tool` messages | alternating `user` / `assistant` turns; `tool_calls` → `tool_use` blocks, `tool` messages → `tool_result` blocks merged into one `user` turn |
| `tools` (function) | `tools` with `input_schema` (after the gateway's schema sanitizer) |
| `tool_choice`, `parallel_tool_calls` | `tool_choice` `auto` / `any` / `tool` / `none`, `disable_parallel_tool_use` |
| `response_format: json_schema` | `output_config.format` (structured outputs) |
| `max_tokens` (clamped by the gateway) | `max_tokens` |
| `stop` | `stop_sequences` |
| `chat_template_kwargs.enable_thinking` | `thinking: {type: adaptive}` — only when `TALAHON_ANTHROPIC_THINKING=true` |
| `temperature`, `top_p`, `top_k`, penalties, `seed` | dropped (current Claude models reject sampling parameters) |
| `cache_salt` | not sent (Anthropic's prompt cache is keyed by the exact prefix and scoped to the organisation) |
| `/v1/models` | answered from the gateway's allow-list, no upstream call |
| `/tokenize` | `POST /v1/messages/count_tokens` |

Responses come back as `chat.completion` / `chat.completion.chunk` with
`usage.prompt_tokens_details.cached_tokens` = `cache_read_input_tokens`, so
the usage accounting and `cache_read_input_tokens` reporting work unchanged.

**Thinking.** Off by default. With `TALAHON_ANTHROPIC_THINKING=true` the
gateway requests adaptive thinking. The API requires the signed `thinking`
blocks of an assistant turn to be replayed when its tool calls are answered;
the OpenAI shape has no place for them, so the gateway appends them to
`reasoning_content` as an opaque `<talon-thinking>…</talon-thinking>` marker
(hex-encoded JSON) after the readable thinking text, and restores them from
the history the agent sends back. Readable thinking text is only present when
the model's `display` setting returns it.

**Egress.** The host process (not a container) connects to
`api.anthropic.com:443`; `talahon setup egress` is about container egress and
needs no change. Rate limits and overloads come back to the agent as
`429` / `529` with the Anthropic error message in the OpenAI error shape; the
client's retry/backoff applies.
