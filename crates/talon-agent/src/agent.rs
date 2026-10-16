//! The agent loop.
//!
//! ```text
//! run_session(first prompt)
//!   loop:
//!     run_turn(prompt) ──▶ frame: success(result, session id) + usage of the turn
//!     _close seen during the turn? ──▶ end
//!     wait for IPC input (poll) ──▶ next prompt | _close / cancel ──▶ end
//!
//! run_turn(prompt)
//!   push user message
//!   loop (iteration < max_iterations):
//!     pipe newly arrived IPC messages in as user messages (iteration > 0)
//!     compact if the prompt is above the threshold
//!     chat (tools, tool_choice=auto, parallel_tool_calls) — on a context
//!       overflow: compact and retry once
//!     no tool calls ──▶ final answer
//!     answer every call: unknown tool / bad JSON ─▶ error result;
//!       loop guard (3x identical ─▶ nudge, 5x ─▶ stop the turn);
//!       read-only calls in parallel, exclusive ones in order;
//!       results truncated to a context-relative budget
//!   budget exhausted / loop ─▶ forced final answer (tool_choice=none)
//!   investigation: self-check pass, then a guided-decoding triage report
//!     if `submit_triage_report` exists and was not called successfully
//! ```

use std::sync::Arc;
use std::time::Instant;

use talon_core::protocol::ContainerOutput;
use talon_core::tool::ToolContext;
use talon_llm::{
    ChatBackend, ChatMessage, ChatRequest, ChatResponse, LlmError, Role, StreamEvent, ToolChoice,
    Usage, estimate_conversation_tokens,
};

use crate::compact::{self, Summary};
use crate::config::LoopSettings;
use crate::error::AgentError;
use crate::ipc::{Inbound, IpcInbox};
use crate::model::ModelSettings;
use crate::prompt::{self, SUBMIT_TRIAGE_REPORT};
use crate::session::SessionStore;
use crate::tools::{self, CallKind, LoopGuard, LoopVerdict, ToolRegistry};
use crate::wire::OutputSink;

/// Where compaction archives go and how they are labelled.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// Lane-private archive directory (`<state>/conversations`, see
    /// [`crate::config::AgentPaths::conversations`]); `None` disables
    /// archiving.
    pub dir: Option<std::path::PathBuf>,
    /// Name used for assistant lines in the archive.
    pub assistant_name: String,
    /// Timezone for archive dates.
    pub timezone: chrono_tz::Tz,
}

/// Everything an [`Agent`] is made of.
pub struct AgentParts {
    /// The model.
    pub backend: Arc<dyn ChatBackend>,
    /// Model names, sampling, context window.
    pub model: ModelSettings,
    /// Tools offered to the model.
    pub tools: Arc<ToolRegistry>,
    /// Context passed to every tool call (its token cancels the run).
    pub tool_ctx: ToolContext,
    /// The byte-stable system prompt.
    pub system_prompt: String,
    /// Output frames.
    pub output: Arc<dyn OutputSink>,
    /// IPC follow-ups and `_close`.
    pub inbox: IpcInbox,
    /// Transcript persistence.
    pub store: SessionStore,
    /// Loaded history (resumed sessions) — without the system prompt.
    pub history: Vec<ChatMessage>,
    /// Loop limits.
    pub settings: LoopSettings,
    /// Compaction archive settings.
    pub archive: ArchiveOptions,
    /// SOC investigation run (self-check, triage report).
    pub investigation: bool,
}

/// Result of one turn.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TurnOutcome {
    /// Final answer (`None` if empty).
    pub result: Option<String>,
    /// Token usage summed over every model call of the turn.
    pub usage: Usage,
    /// `_close` arrived during the turn: end the session after it.
    pub close_requested: bool,
    /// Model calls with tools made.
    pub iterations: u32,
    /// Tool calls answered.
    pub tool_calls: u32,
    /// The final answer was forced (budget or loop).
    pub forced: bool,
    /// The context was compacted during the turn.
    pub compactions: u32,
}

/// How [`Agent::compact`] chooses what to keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactMode {
    /// Keep the most recent turns (threshold or overflow).
    KeepRecent,
    /// Summarize everything (`/compact`).
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolMode {
    Auto,
    Off,
}

#[derive(Debug, Default)]
struct TurnState {
    usage: Usage,
    close_requested: bool,
    tool_calls: u32,
    report_submitted: bool,
    compactions: u32,
}

/// The agent: a conversation plus everything needed to continue it.
pub struct Agent {
    backend: Arc<dyn ChatBackend>,
    model: ModelSettings,
    tools: Arc<ToolRegistry>,
    tool_ctx: ToolContext,
    system_prompt: String,
    output: Arc<dyn OutputSink>,
    inbox: IpcInbox,
    store: SessionStore,
    history: Vec<ChatMessage>,
    settings: LoopSettings,
    archive: ArchiveOptions,
    investigation: bool,
    call_seq: u64,
    /// IPC input files consumed since the last output frame.
    consumed: Vec<String>,
}

impl std::fmt::Debug for Agent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent")
            .field("session", &self.store.id())
            .field("history", &self.history.len())
            .field("tools", &self.tools.len())
            .field("investigation", &self.investigation)
            .finish_non_exhaustive()
    }
}

impl Agent {
    /// Assemble an agent.
    pub fn new(parts: AgentParts) -> Self {
        Self {
            backend: parts.backend,
            model: parts.model,
            tools: parts.tools,
            tool_ctx: parts.tool_ctx,
            system_prompt: parts.system_prompt,
            output: parts.output,
            inbox: parts.inbox,
            store: parts.store,
            history: parts.history,
            settings: parts.settings,
            archive: parts.archive,
            investigation: parts.investigation,
            call_seq: 0,
            consumed: Vec::new(),
        }
    }

    /// Record IPC input files whose messages are part of the next turn's
    /// prompt (follow-ups drained before the session started).
    pub fn note_consumed(&mut self, files: impl IntoIterator<Item = String>) {
        self.consumed.extend(files);
    }

    /// The IPC input files consumed since the last frame, for the next
    /// frame (cleared).
    pub fn take_consumed(&mut self) -> Vec<String> {
        std::mem::take(&mut self.consumed)
    }

    /// The conversation so far (without the system prompt).
    pub fn history(&self) -> &[ChatMessage] {
        &self.history
    }

    /// The session id.
    pub fn session_id(&self) -> &str {
        self.store.id()
    }

    /// The session id to report to the host (`None` for ephemeral
    /// sessions, which cannot be resumed).
    pub fn reported_session_id(&self) -> Option<String> {
        self.store
            .is_persistent()
            .then(|| self.store.id().to_string())
    }

    /// The system prompt in use.
    pub fn system_prompt(&self) -> &str {
        &self.system_prompt
    }

    /// Run turns until `_close`, cancellation, or a fatal error. Emits one
    /// success frame per turn. The caller emits the error frame on `Err`.
    pub async fn run_session(&mut self, first_prompt: String) -> Result<(), AgentError> {
        let mut prompt = first_prompt;
        loop {
            let started = Instant::now();
            let outcome = self.run_turn(prompt).await?;
            tracing::info!(
                iterations = outcome.iterations,
                tool_calls = outcome.tool_calls,
                forced = outcome.forced,
                compactions = outcome.compactions,
                prompt_tokens = outcome.usage.prompt_tokens,
                cached_tokens = outcome.usage.cached_tokens,
                completion_tokens = outcome.usage.completion_tokens,
                result_chars = outcome.result.as_deref().map_or(0, str::len),
                ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "turn complete"
            );
            let mut frame =
                ContainerOutput::success(outcome.result.clone(), self.reported_session_id());
            frame.usage = Some((&outcome.usage).into());
            frame.consumed_inputs = Some(self.take_consumed());
            self.output.emit(&frame);
            if outcome.close_requested {
                tracing::info!("close sentinel consumed during the turn; ending session");
                return Ok(());
            }
            tracing::debug!("waiting for the next IPC message");
            match self
                .inbox
                .wait_next(self.settings.ipc_poll, &self.tool_ctx.cancel)
                .await
            {
                Inbound::Messages { text, files } => {
                    tracing::info!(
                        chars = text.len(),
                        "follow-up message received; starting a new turn"
                    );
                    self.consumed.extend(files);
                    prompt = self.with_turn_header(&text);
                }
                Inbound::Close => {
                    tracing::info!("close sentinel received; ending session");
                    return Ok(());
                }
                Inbound::Cancelled => {
                    tracing::info!("cancelled while idle; ending session");
                    return Ok(());
                }
            }
        }
    }

    /// Prefix `text` with the current-time header (start of a turn).
    pub fn with_turn_header(&self, text: &str) -> String {
        format!(
            "{}\n\n{text}",
            prompt::time_header(chrono::Utc::now(), self.archive.timezone.name())
        )
    }

    /// Run one turn for `user_text` and return its outcome (the frame is
    /// emitted by [`Self::run_session`]).
    pub async fn run_turn(&mut self, user_text: String) -> Result<TurnOutcome, AgentError> {
        let mut st = TurnState::default();
        self.push(ChatMessage::user(user_text));
        let mut guard = LoopGuard::new(self.settings.loop_nudge_at, self.settings.loop_stop_at);
        let mut iteration: u32 = 0;
        let mut forced = false;
        let mut final_message = loop {
            self.check_cancel()?;
            if iteration > 0 {
                self.absorb_ipc(&mut st);
            }
            if iteration >= self.settings.max_iterations {
                tracing::warn!(
                    iterations = iteration,
                    "tool-call budget exhausted; forcing a final answer"
                );
                forced = true;
                break self
                    .forced_final(prompt::FORCE_FINAL_BUDGET, &mut st)
                    .await?;
            }
            let resp = self.complete(ToolMode::Auto, &[], &mut st).await?;
            iteration += 1;
            let mut message = resp.message;
            if !message.has_tool_calls() {
                if resp.finish_reason == Some(talon_llm::FinishReason::Length) {
                    tracing::warn!("final answer was cut off by max_tokens");
                }
                break message;
            }
            self.call_seq += 1;
            tools::ensure_call_ids(&mut message.tool_calls, self.call_seq);
            let prepared: Vec<tools::PreparedCall> = message
                .tool_calls
                .iter()
                .map(|c| tools::prepare_call(&self.tools, c))
                .collect();
            let fixed = message.normalize_tool_arguments();
            if fixed > 0 {
                tracing::warn!(count = fixed, "model produced malformed tool arguments");
            }
            message.content = message.content.filter(|c| !c.trim().is_empty());
            self.push(message);

            let mut nudges: Vec<Option<u32>> = vec![None; prepared.len()];
            let mut stop = false;
            for (i, p) in prepared.iter().enumerate() {
                if let CallKind::Ready { args, .. } = &p.kind {
                    match guard.record(&p.name, args) {
                        LoopVerdict::Ok => {}
                        LoopVerdict::Nudge(n) => nudges[i] = Some(n),
                        LoopVerdict::Stop(n) => {
                            tracing::warn!(tool = %p.name, repeats = n, "tool-call loop detected; stopping the turn");
                            stop = true;
                        }
                    }
                }
            }
            if stop {
                for p in &prepared {
                    self.push(ChatMessage::tool_result(
                        p.id.clone(),
                        "[talon] Not executed: the same call was repeated too many times.",
                    ));
                }
                st.tool_calls += u32::try_from(prepared.len()).unwrap_or(u32::MAX);
                forced = true;
                break self.forced_final(prompt::FORCE_FINAL_LOOP, &mut st).await?;
            }

            let names: Vec<&str> = prepared.iter().map(|p| p.name.as_str()).collect();
            tracing::info!(iteration, calls = prepared.len(), tools = ?names, "executing tool calls");
            let outputs =
                tools::execute_calls(&prepared, &self.tool_ctx, self.settings.tool_timeout).await;
            let budget = tools::result_budget_bytes(self.model.max_context_tokens, prepared.len());
            for ((p, out), nudge) in prepared.iter().zip(outputs).zip(nudges) {
                if p.name == SUBMIT_TRIAGE_REPORT && !out.is_error {
                    st.report_submitted = true;
                }
                let mut content = tools::render_output(&out, budget);
                if let Some(n) = nudge {
                    content.push_str(&prompt::loop_nudge(&p.name, n));
                }
                self.push(ChatMessage::tool_result(p.id.clone(), content));
            }
            st.tool_calls += u32::try_from(prepared.len()).unwrap_or(u32::MAX);
        };

        if final_message.text().trim().is_empty() {
            tracing::warn!("model returned an empty final answer");
        }
        if self.investigation && self.settings.self_check && st.tool_calls > 0 {
            if let Some(revised) = self.self_check(&final_message, &mut st).await? {
                final_message = ChatMessage::assistant(revised);
            }
        }
        final_message.tool_calls.clear();
        if final_message.content.is_none() {
            // Keep the history renderable by every chat template.
            final_message.content = Some(String::new());
        }
        self.push(final_message.clone());
        if self.investigation && !st.report_submitted && self.tools.contains(SUBMIT_TRIAGE_REPORT) {
            self.ensure_report(&mut st).await?;
        }

        let result = final_message.text().trim().to_string();
        Ok(TurnOutcome {
            result: (!result.is_empty()).then_some(result),
            usage: st.usage,
            close_requested: st.close_requested,
            iterations: iteration,
            tool_calls: st.tool_calls,
            forced,
            compactions: st.compactions,
        })
    }

    fn check_cancel(&self) -> Result<(), AgentError> {
        if self.tool_ctx.cancel.is_cancelled() {
            Err(AgentError::Cancelled)
        } else {
            Ok(())
        }
    }

    fn push(&mut self, message: ChatMessage) {
        if let Err(e) = self.store.append(&message) {
            tracing::error!(error = %e, "cannot append to the session transcript");
        }
        self.history.push(message);
    }

    fn absorb_ipc(&mut self, st: &mut TurnState) {
        if st.close_requested {
            return;
        }
        // `_close` first, then the messages: everything written before
        // `_close` is in place by then and still goes into this turn.
        let closing = self.inbox.close_pending();
        let messages = self.inbox.drain();
        if !messages.is_empty() {
            tracing::info!(
                count = messages.len(),
                "piping follow-up messages into the active turn"
            );
            let (texts, files): (Vec<String>, Vec<String>) =
                messages.into_iter().map(|m| (m.text, m.file)).unzip();
            self.consumed.extend(files);
            self.push(ChatMessage::user(texts.join("\n")));
        }
        if closing {
            tracing::info!("close sentinel received during the turn; finishing it first");
            self.inbox.take_close();
            st.close_requested = true;
        }
    }

    fn messages_with(&self, extra: &[ChatMessage]) -> Vec<ChatMessage> {
        let mut v = Vec::with_capacity(self.history.len() + extra.len() + 1);
        v.push(ChatMessage::system(self.system_prompt.clone()));
        v.extend(self.history.iter().cloned());
        v.extend(extra.iter().cloned());
        v
    }

    fn build_request(&self, mode: ToolMode, extra: &[ChatMessage]) -> ChatRequest {
        let req = self.model.request(self.messages_with(extra));
        if self.tools.is_empty() {
            return req;
        }
        // Tools are always listed (even when disabled) so the rendered
        // prompt prefix stays identical for vLLM's prefix cache.
        let req = req.tool_definitions(self.tools.definitions().to_vec());
        match mode {
            ToolMode::Auto => req.tool_choice(ToolChoice::Auto).parallel_tool_calls(true),
            ToolMode::Off => req.tool_choice(ToolChoice::None),
        }
    }

    async fn call_backend(&self, req: &ChatRequest) -> Result<ChatResponse, AgentError> {
        let started = Instant::now();
        let mut streamed_chars = 0usize;
        let mut sink = |ev: &StreamEvent| {
            if let StreamEvent::Content(t) | StreamEvent::Reasoning(t) = ev {
                streamed_chars += t.len();
            }
        };
        let result = tokio::select! {
            r = self.backend.complete(req, &mut sink) => r,
            _ = self.tool_ctx.cancel.cancelled() => return Err(AgentError::Cancelled),
        };
        let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(resp) => tracing::debug!(
                model = %req.model,
                ms,
                streamed_chars,
                tool_calls = resp.message.tool_calls.len(),
                finish = ?resp.finish_reason,
                prompt_tokens = resp.usage.prompt_tokens,
                "model call finished"
            ),
            Err(e) => tracing::warn!(model = %req.model, ms, kind = e.kind(), "model call failed"),
        }
        result.map_err(AgentError::from)
    }

    /// Main-model completion with threshold compaction before the request
    /// and one compact-and-retry on a context overflow.
    async fn complete(
        &mut self,
        mode: ToolMode,
        extra: &[ChatMessage],
        st: &mut TurnState,
    ) -> Result<ChatResponse, AgentError> {
        if self.maybe_compact().await? {
            st.compactions += 1;
        }
        let mut retried = false;
        loop {
            let req = self.build_request(mode, extra);
            match self.call_backend(&req).await {
                Ok(resp) => {
                    st.usage += resp.usage;
                    return Ok(resp);
                }
                Err(AgentError::Llm(LlmError::ContextLengthExceeded(msg))) if !retried => {
                    tracing::warn!("context length exceeded; compacting and retrying once");
                    retried = true;
                    if !self.compact(CompactMode::KeepRecent).await? {
                        return Err(AgentError::ContextOverflow(msg));
                    }
                    st.compactions += 1;
                }
                Err(AgentError::Llm(LlmError::ContextLengthExceeded(msg))) => {
                    return Err(AgentError::ContextOverflow(msg));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Compact when the prompt is above the threshold. Returns whether it
    /// compacted.
    async fn maybe_compact(&mut self) -> Result<bool, AgentError> {
        let threshold = self.model.compaction_threshold(self.settings.compact_ratio);
        let messages = self.messages_with(&[]);
        let estimate = estimate_conversation_tokens(&messages, self.tools.definitions());
        // The estimate (~4 chars/token) undercounts JSON-heavy prompts; only
        // ask the server for an exact count when it could matter.
        if estimate.saturating_mul(3) / 2 < threshold {
            return Ok(false);
        }
        let count = self
            .backend
            .count_tokens(&messages, self.tools.definitions())
            .await;
        if count.count <= threshold {
            return Ok(false);
        }
        tracing::info!(
            tokens = count.count,
            estimated = count.estimated,
            threshold,
            "context above the compaction threshold"
        );
        self.compact(CompactMode::KeepRecent).await
    }

    /// Summarize part of the history with the fast model, archive the
    /// pre-compaction transcript and rewrite the session. Returns `false`
    /// when there was nothing to compact.
    pub async fn compact(&mut self, mode: CompactMode) -> Result<bool, AgentError> {
        let cut = match mode {
            CompactMode::All => Some(self.history.len()).filter(|n| *n > 0),
            CompactMode::KeepRecent => compact::choose_cut(
                &self.history,
                self.settings.keep_recent_turns,
                self.model.keep_budget(),
            ),
        };
        let Some(cut) = cut else {
            tracing::info!("nothing to compact");
            return Ok(false);
        };
        let started = Instant::now();
        let head = &self.history[..cut];
        let summary = self.summarize(head).await?;
        let archived = self.archive_transcript(summary.title.as_deref());
        let tail: Vec<ChatMessage> = self.history[cut..].to_vec();
        let tail_starts_with_user = tail.first().is_none_or(|m| m.role == Role::User);
        let mut new_history = compact::summary_messages(&summary, tail_starts_with_user);
        new_history.extend(tail);
        let before = self.history.len();
        self.history = new_history;
        if let Err(e) = self.store.rewrite(&self.history, archived.as_deref()) {
            tracing::error!(error = %e, "cannot rewrite the session transcript after compaction");
        }
        tracing::info!(
            summarized = cut,
            before,
            after = self.history.len(),
            ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "conversation compacted"
        );
        Ok(true)
    }

    async fn summarize(&self, head: &[ChatMessage]) -> Result<Summary, AgentError> {
        let max_tokens = self.model.summary_max_tokens();
        // Leave room for the summary itself and the summarizer prompt.
        let input_tokens = self
            .model
            .max_context_tokens
            .saturating_sub(u64::from(max_tokens) + 1_024)
            .max(1_024);
        let max_chars = usize::try_from(input_tokens.saturating_mul(3)).unwrap_or(usize::MAX);
        let req = self.model.fast_request(
            compact::summary_request_messages(head, max_chars),
            max_tokens,
        );
        match self.call_backend(&req).await {
            Ok(resp) => match compact::parse_summary(resp.message.text()) {
                Some(s) => Ok(s),
                None => {
                    tracing::warn!("summarizer returned nothing; using a mechanical summary");
                    Ok(compact::fallback_summary(head))
                }
            },
            Err(AgentError::Cancelled) => Err(AgentError::Cancelled),
            Err(e) => {
                tracing::warn!(
                    kind = e.kind(),
                    "summarization failed; using a mechanical summary"
                );
                Ok(compact::fallback_summary(head))
            }
        }
    }

    fn archive_transcript(&self, title: Option<&str>) -> Option<std::path::PathBuf> {
        let dir = self.archive.dir.as_ref()?;
        let now = compact::now_in(self.archive.timezone);
        let markdown =
            compact::archive_markdown(&self.history, title, &self.archive.assistant_name, now);
        match compact::write_archive(dir, now, title, &markdown) {
            Ok(path) => {
                tracing::info!(path = %path.display(), "archived conversation before compaction");
                Some(path)
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot archive the conversation");
                None
            }
        }
    }

    async fn forced_final(
        &mut self,
        instruction: &str,
        st: &mut TurnState,
    ) -> Result<ChatMessage, AgentError> {
        self.push(ChatMessage::user(instruction));
        let resp = self.complete(ToolMode::Off, &[], st).await?;
        let mut message = resp.message;
        if message.has_tool_calls() {
            tracing::warn!("model requested tools in a forced final answer; ignoring them");
            message.tool_calls.clear();
        }
        // With tools disabled the client does not strip tool-call markup the
        // model may still write as text; never deliver it as the answer.
        if let Some(parsed) = talon_llm::parse_text_tool_calls(message.text(), &|_| true) {
            if !parsed.calls.is_empty() || !parsed.rejected.is_empty() {
                message.content = Some(parsed.content.trim().to_string());
            }
        }
        if message.text().trim().is_empty() {
            message.content = Some(prompt::EMPTY_ANSWER_FALLBACK.to_string());
        }
        Ok(message)
    }

    /// Ask the model to verify its draft against the tool evidence. Returns
    /// the revised answer, or `None` to keep the draft.
    async fn self_check(
        &mut self,
        draft: &ChatMessage,
        st: &mut TurnState,
    ) -> Result<Option<String>, AgentError> {
        let draft_text = draft.text().trim().to_string();
        if draft_text.is_empty() {
            return Ok(None);
        }
        let extra = [
            ChatMessage::assistant(draft_text.clone()),
            ChatMessage::user(prompt::SELF_CHECK_PROMPT),
        ];
        let req = self.build_request(ToolMode::Off, &extra);
        let resp = match self.call_backend(&req).await {
            Ok(r) => r,
            Err(AgentError::Cancelled) => return Err(AgentError::Cancelled),
            Err(e) => {
                tracing::warn!(
                    kind = e.kind(),
                    "self-check failed; keeping the draft answer"
                );
                return Ok(None);
            }
        };
        st.usage += resp.usage;
        let revised = resp.message.text().trim().to_string();
        if resp.message.has_tool_calls()
            || revised.is_empty()
            || revised.len() * 3 < draft_text.len()
        {
            tracing::info!("self-check reply unusable; keeping the draft answer");
            return Ok(None);
        }
        tracing::info!(changed = revised != draft_text, "self-check complete");
        Ok(Some(revised))
    }

    /// Produce the structured triage report with guided decoding
    /// (`talon_intel::report::guided_json_schema`), clamp it to the schema
    /// limits and submit it through `submit_triage_report` (which sanitizes,
    /// validates and persists it). Failures are logged, never fatal.
    async fn ensure_report(&mut self, st: &mut TurnState) -> Result<(), AgentError> {
        let Some(tool) = self.tools.get(SUBMIT_TRIAGE_REPORT) else {
            return Ok(());
        };
        let mut req = self
            .model
            .request(self.messages_with(&[ChatMessage::user(prompt::REPORT_PROMPT)]))
            .json_schema(
                "triage_report",
                talon_intel::report::guided_json_schema(),
                true,
            );
        if self.model.enable_thinking.is_some() {
            req = req.enable_thinking(false);
        }
        tracing::info!("no triage report submitted; generating one with guided decoding");
        let resp = match self.call_backend(&req).await {
            Ok(r) => r,
            Err(AgentError::Cancelled) => return Err(AgentError::Cancelled),
            Err(e) => {
                tracing::warn!(kind = e.kind(), "triage report generation failed");
                return Ok(());
            }
        };
        st.usage += resp.usage;
        let decoded = match resp.content_json() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("guided triage report is not valid JSON");
                return Ok(());
            }
        };
        let mut report = match talon_intel::TriageReport::from_json(&decoded) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "guided triage report does not match the schema");
                return Ok(());
            }
        };
        report.clamp_to_limits();
        let report_json = match serde_json::to_value(&report) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "cannot encode the triage report");
                return Ok(());
            }
        };
        let out = tools::invoke(
            tool,
            serde_json::json!({ "report": report_json }),
            self.tool_ctx.clone(),
            self.settings.tool_timeout,
            SUBMIT_TRIAGE_REPORT,
        )
        .await;
        if out.is_error {
            tracing::warn!("guided triage report was rejected by submit_triage_report");
        } else {
            st.report_submitted = true;
            tracing::info!("structured triage report submitted");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
