# Model Provider: vLLM or Anthropic

Talon's agent loop speaks the OpenAI-compatible chat API to the **host LLM
gateway**. What the gateway talks to is the provider:

| `TALON_PROVIDER` | upstream | notes |
|---|---|---|
| `vllm` (default) | your vLLM server | passthrough, see below |
| `anthropic` | Anthropic Messages API | translated in the gateway, see [Anthropic](#anthropic) |


Talon 2.0 runs its agents against a **vLLM** server through vLLM's
OpenAI-compatible API (`/v1/chat/completions` with tool calling and
structured outputs). The agent loop is native Rust (`crates/talon-agent`),
so any model vLLM can serve with a working tool-call parser can drive an
investigation.

## TL;DR

```bash
# /opt/talon/.env
TALON_VLLM_BASE_URL=http://vllm.internal:8000
TALON_VLLM_MODEL=Qwen/Qwen3-32B
TALON_VLLM_FAST_MODEL=Qwen/Qwen3-8B        # optional: compaction / extraction
TALON_VLLM_MAX_CONTEXT=131072              # model context window (tokens)
TALON_VLLM_API_KEY=...                     # only if vLLM runs with --api-key
```

Restart Talon. Every group inherits the provider; per-group overrides live in
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
| Qwen2.5 / Qwen3 (instruct) | `hermes` | Qwen3: add `--reasoning-parser qwen3`; `TALON_VLLM_ENABLE_THINKING` toggles thinking |
| Llama 3.1 / 3.3 | `llama3_json` | 70B recommended for full investigations |
| Mistral / Mistral-Small | `mistral` | |
| DeepSeek-V3 / R1 distills | `deepseek_v3` / `hermes` | |

If a model or server emits tool calls as plain text anyway (Hermes
`<tool_call>`, Mistral `[TOOL_CALLS]`, Llama `<|python_tag|>`, fenced JSON),
`talon-llm` recovers them client-side and only accepts tools that were
actually offered.

**Prefix caching matters.** Talon keeps the system prompt byte-stable across
turns (volatile data such as the current time goes into the first user
message), so `--enable-prefix-caching` turns most of each turn's prompt into
cache hits. Cache hits are reported back to the host as
`cache_read_input_tokens`.

## How requests flow

```
talon-agent (container) ──Bearer <per-run token>──▶ talon LLM gateway (host) ──Bearer <vLLM key>──▶ vLLM
```

The host starts an LLM gateway (`crates/talon-llm`, default
`TALON_LLM_GATEWAY_PORT=3001`, bound to the docker bridge address on Linux).
For every container run it issues a short-lived token and passes the
endpoint to the container **over stdin** — never in environment variables, so
it is invisible to `docker inspect` and to tool subprocesses. The gateway:

- validates the per-run token (stored only as a SHA-256 digest; revoked when
  the run ends),
- injects the real vLLM API key, which never enters a container,
- pins the model to the configured allow-list (unknown model -> default),
- clamps `max_tokens`, forces `n = 1`, strips server-side knobs such as
  `chat_template`, `logits_processors`, `best_of`, `vllm_xargs`,
- rate-limits and concurrency-limits per token, caps body size,
- counts usage per group and audits authentication failures.

## Settings

| Key | Default | Meaning |
|---|---|---|
| `TALON_VLLM_BASE_URL` | — | vLLM server URL (required) |
| `TALON_VLLM_MODEL` | — | served model name (required) |
| `TALON_VLLM_FAST_MODEL` | `MODEL` | auxiliary model for compaction / summarisation |
| `TALON_VLLM_MAX_CONTEXT` | 32768 | context window; drives compaction (~75 %) |
| `TALON_VLLM_MAX_OUTPUT` | — | max output tokens per completion |
| `TALON_VLLM_TEMPERATURE`, `TALON_VLLM_TOP_P` | server default | sampling |
| `TALON_VLLM_ENABLE_THINKING` | — | `chat_template_kwargs.enable_thinking` |
| `TALON_VLLM_TIMEOUT_SECS` | — | per-request timeout |
| `TALON_VLLM_API_KEY` | — | secret; read from `.env` only, held by the gateway |
| `TALON_LLM_GATEWAY_PORT` | 3001 | gateway port |
| `TALON_LLM_GATEWAY_BIND` | auto | override the auto-detected bind address |
| `TALON_BLOCKED_HOSTS` | — | hosts routed to 127.0.0.1 in every container |

`TALON_PROVIDER` values other than `vllm` are ignored with a warning, and
stored group configs that name another provider fall back to the `.env` vLLM
defaults.

## Model selection

Practical floor for the full SOC investigation flow (10 MCP servers, 100+
tools, multi-step reasoning) is a strong ~30B instruct model; 70B-class or
large MoE models give the most reliable tool discipline. Pair a large primary
model with a small `TALON_VLLM_FAST_MODEL` for compaction to keep long
sessions cheap.

## Verifying

```bash
talon setup vllm      # probes <base>/v1/models, checks MODEL and FAST_MODEL are served
talon doctor          # environment + container + gateway + vLLM in one report
```

## Anthropic

```bash
# /opt/talon/.env
TALON_PROVIDER=anthropic
TALON_ANTHROPIC_MODEL=claude-sonnet-5-5
TALON_ANTHROPIC_FAST_MODEL=claude-haiku-5-5   # optional
TALON_ANTHROPIC_MAX_CONTEXT=200000
TALON_ANTHROPIC_API_KEY=...                   # host only, like TALON_VLLM_API_KEY
```

Then `talon setup vllm` (probes `GET /v1/models` with the key) and
`talon doctor` as usual. Nothing changes inside the container: the agent
keeps calling `/v1/chat/completions` on the gateway with its per-run token,
and the gateway translates (`crates/talon-llm/src/anthropic/`):

| OpenAI chat field | Messages API |
|---|---|
| `system` messages | `system` text blocks, one `cache_control: ephemeral` breakpoint (Talon's system prompt is byte-stable, so every turn after the first is a cache hit) |
| `user` / `assistant` / `tool` messages | alternating `user` / `assistant` turns; `tool_calls` → `tool_use` blocks, `tool` messages → `tool_result` blocks merged into one `user` turn |
| `tools` (function) | `tools` with `input_schema` (after the gateway's schema sanitizer) |
| `tool_choice`, `parallel_tool_calls` | `tool_choice` `auto` / `any` / `tool` / `none`, `disable_parallel_tool_use` |
| `response_format: json_schema` | `output_config.format` (structured outputs) |
| `max_tokens` (clamped by the gateway) | `max_tokens` |
| `stop` | `stop_sequences` |
| `chat_template_kwargs.enable_thinking` | `thinking: {type: adaptive}` — only when `TALON_ANTHROPIC_THINKING=true` |
| `temperature`, `top_p`, `top_k`, penalties, `seed` | dropped (current Claude models reject sampling parameters) |
| `cache_salt` | not sent (Anthropic's prompt cache is keyed by the exact prefix and scoped to the organisation) |
| `/v1/models` | answered from the gateway's allow-list, no upstream call |
| `/tokenize` | `POST /v1/messages/count_tokens` |

Responses come back as `chat.completion` / `chat.completion.chunk` with
`usage.prompt_tokens_details.cached_tokens` = `cache_read_input_tokens`, so
the usage accounting and `cache_read_input_tokens` reporting work unchanged.

**Thinking.** Off by default. With `TALON_ANTHROPIC_THINKING=true` the
gateway requests adaptive thinking. The API requires the signed `thinking`
blocks of an assistant turn to be replayed when its tool calls are answered;
the OpenAI shape has no place for them, so the gateway appends them to
`reasoning_content` as an opaque `<talon-thinking>…</talon-thinking>` marker
(hex-encoded JSON) after the readable thinking text, and restores them from
the history the agent sends back. Readable thinking text is only present when
the model's `display` setting returns it.

**Egress.** The host process (not a container) connects to
`api.anthropic.com:443`; `talon setup egress` is about container egress and
needs no change. Rate limits and overloads come back to the agent as
`429` / `529` with the Anthropic error message in the OpenAI error shape; the
client's retry/backoff applies.
