//! The SSE response body for `POST /message`.
//!
//! The stream yields the frames queued on its writer and ends when the
//! writer is closed (its sender dropped). When the client disconnects, hyper
//! drops the body, and the guard removes the writer from its lane so output
//! is never written into a dead stream and the lane can be swept.

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::response::sse::Event;
use futures::Stream;
use tokio::sync::mpsc;

use crate::lanes::{SseFrame, StreamRegistry};

/// Removes a writer from its lane when dropped.
pub(crate) struct WriterGuard {
    pub registry: Arc<StreamRegistry>,
    pub jid: String,
    pub id: u64,
}

impl Drop for WriterGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.jid, self.id);
    }
}

/// Stream of SSE events for one writer.
pub(crate) struct WriterStream {
    rx: mpsc::Receiver<SseFrame>,
    _guard: WriterGuard,
}

impl WriterStream {
    pub(crate) fn new(rx: mpsc::Receiver<SseFrame>, guard: WriterGuard) -> Self {
        Self { rx, _guard: guard }
    }
}

impl Stream for WriterStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx
            .poll_recv(cx)
            .map(|frame| frame.map(|f| Ok(Event::default().data(f.to_json()))))
    }
}
