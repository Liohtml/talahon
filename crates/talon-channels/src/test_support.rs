//! Test doubles shared by the channel tests.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use talon_core::channel::ChannelHost;
use talon_core::types::{ChatMetadata, NewMessage, RegisteredGroup};

/// One host callback, in call order.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum HostEvent {
    Metadata(ChatMetadata),
    Message(String, NewMessage),
    Register(String, RegisteredGroup, bool),
}

/// [`ChannelHost`] that records every callback.
#[derive(Debug, Default)]
pub struct RecordingHost {
    pub groups: Mutex<HashMap<String, RegisteredGroup>>,
    pub events: Mutex<Vec<HostEvent>>,
}

impl RecordingHost {
    pub fn with_groups(groups: &[(&str, RegisteredGroup)]) -> Self {
        let host = Self::default();
        {
            let mut g = host.groups.lock().unwrap();
            for (jid, group) in groups {
                g.insert((*jid).to_string(), group.clone());
            }
        }
        host
    }

    pub fn events(&self) -> Vec<HostEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn messages(&self) -> Vec<(String, NewMessage)> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                HostEvent::Message(jid, m) => Some((jid, m)),
                _ => None,
            })
            .collect()
    }

    pub fn metadata(&self) -> Vec<ChatMetadata> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                HostEvent::Metadata(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    pub fn registrations(&self) -> Vec<(String, RegisteredGroup, bool)> {
        self.events()
            .into_iter()
            .filter_map(|e| match e {
                HostEvent::Register(jid, g, persist) => Some((jid, g, persist)),
                _ => None,
            })
            .collect()
    }

    /// Wait (bounded) until at least `n` messages arrived.
    pub async fn wait_for_messages(&self, n: usize) -> Vec<(String, NewMessage)> {
        for _ in 0..200 {
            let msgs = self.messages();
            if msgs.len() >= n {
                return msgs;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        self.messages()
    }
}

#[async_trait]
impl ChannelHost for RecordingHost {
    async fn on_message(&self, chat_jid: &str, message: NewMessage) {
        self.events
            .lock()
            .unwrap()
            .push(HostEvent::Message(chat_jid.to_string(), message));
    }

    async fn on_chat_metadata(&self, metadata: ChatMetadata) {
        self.events
            .lock()
            .unwrap()
            .push(HostEvent::Metadata(metadata));
    }

    fn registered_groups(&self) -> HashMap<String, RegisteredGroup> {
        self.groups.lock().unwrap().clone()
    }

    async fn register_group(&self, jid: &str, group: RegisteredGroup, persist: bool) {
        self.groups
            .lock()
            .unwrap()
            .insert(jid.to_string(), group.clone());
        self.events
            .lock()
            .unwrap()
            .push(HostEvent::Register(jid.to_string(), group, persist));
    }

    async fn unregister_group(&self, jid: &str) -> bool {
        self.groups.lock().unwrap().remove(jid).is_some()
    }

    async fn clear_session(&self, _jid: &str) -> bool {
        false
    }

    fn notify_tasks_changed(&self) {}
}

/// A plain registered group.
pub fn group(name: &str, folder: &str, trigger: &str) -> RegisteredGroup {
    RegisteredGroup {
        name: name.to_string(),
        folder: folder.to_string(),
        trigger: trigger.to_string(),
        added_at: "2024-01-01T00:00:00.000Z".to_string(),
        container_config: None,
        requires_trigger: None,
        is_main: false,
        session_key: None,
        ipc_key: None,
        ephemeral_session: false,
        trusted_session_commands: false,
    }
}

/// Local constant-time equality used to keep unit tests independent of
/// `talon-security`.
pub fn test_ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Local HMAC-SHA256 hex (reference implementation from the `hmac` crate).
pub fn test_hmac(key: &[u8], message: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}
