//! Per-chat sender allowlist (port of `src/sender-allowlist.ts`).
//! File: `~/.config/talon/sender-allowlist.json`. Missing file => everyone
//! allowed (legacy behaviour) unless `TALON_SENDER_ALLOWLIST_REQUIRED=true`.

use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct SenderAllowlist {
    // implementation-defined
    #[allow(dead_code)]
    inner: serde_json::Value,
}

#[allow(unused_variables, clippy::todo)]
impl SenderAllowlist {
    pub fn load(path: &Path) -> Self {
        todo!()
    }
    pub fn from_json(value: serde_json::Value) -> Self {
        todo!()
    }
    /// May this sender's messages be processed at all?
    pub fn is_sender_allowed(&self, chat_jid: &str, sender: &str) -> bool {
        todo!()
    }
    /// Drop the message before it is stored (drop mode entries).
    pub fn should_drop_message(&self, chat_jid: &str, sender: &str) -> bool {
        todo!()
    }
    /// May this sender wake the agent with the trigger word?
    pub fn is_trigger_allowed(&self, chat_jid: &str, sender: &str) -> bool {
        todo!()
    }
}
