# Model Provider: vLLM

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
