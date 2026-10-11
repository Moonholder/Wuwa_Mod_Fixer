// src-core/src/events.rs
// Unified progress and feedback stream / pipeline event architecture.
// Decouples src-core from CLI printing, Tauri IPC, and thread synchronization.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, SyncSender, sync_channel},
};

use serde::{Deserialize, Serialize};

use crate::{ProgressReporter, domain::pipeline::PipelineStage};

/// Severity level for structured log / alert events
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventLevel {
    Debug,
    Info,
    Warn,
    Error,
    Success,
}

impl std::fmt::Display for EventLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
            Self::Success => write!(f, "SUCCESS"),
        }
    }
}

/// Processing statistics summary produced upon pipeline completion
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FixSummary {
    pub total_files: usize,
    pub success_count: usize,
    pub skipped_count: usize,
    pub failure_count: usize,
    pub elapsed_ms: u64,
}

/// Unified, structured event emitted across the entire lifecycle of the fixing pipeline
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum PipelineEvent {
    /// Pipeline task execution started
    Start {
        mode: String,
        total: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_time: Option<String>,
    },

    /// Current pipeline processing stage transition
    Stage { stage: PipelineStage, description: String },

    /// Processing started for an individual file
    FileStart {
        path: String,
        current: usize,
        total: usize,
        percent: f64,
    },

    /// Fine-grained step inside an individual file (e.g. character matched, vertex remapped)
    FileStep {
        path: String,
        message_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },

    /// File successfully repaired and written back
    FileSuccess {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        character: Option<String>,
        current: usize,
        total: usize,
        percent: f64,
    },

    /// File skipped without modifications
    FileSkipped {
        path: String,
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason_key: Option<String>,
        current: usize,
        total: usize,
        percent: f64,
    },

    /// An error occurred during file processing
    FileError {
        path: String,
        error: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error_key: Option<String>,
        current: usize,
        total: usize,
        percent: f64,
    },

    /// High-frequency incremental progress report
    Progress {
        current: usize,
        total: usize,
        percent: f64,
        #[serde(skip_serializing_if = "Option::is_none")]
        status_text: Option<String>,
    },

    /// Structured diagnosis / notification event
    Log {
        level: EventLevel,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },

    /// User requested task cancellation
    TaskCancelled { current: usize, total: usize },

    /// Entire pipeline completed
    Finish {
        success: bool,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<FixSummary>,
    },
}

/// Abstract streaming sink for pipeline events
pub trait EventSink: Send + Sync {
    fn emit(&self, event: PipelineEvent);
}

/// No-op event sink (useful for tests or silent executions)
#[derive(Debug, Default, Clone, Copy)]
pub struct NullEventSink;

impl EventSink for NullEventSink {
    #[inline]
    fn emit(&self, _event: PipelineEvent) {}
}

/// Functional closure-based event sink
pub struct FnEventSink<F>(pub F)
where
    F: Fn(PipelineEvent) + Send + Sync;

impl<F> EventSink for FnEventSink<F>
where
    F: Fn(PipelineEvent) + Send + Sync,
{
    fn emit(&self, event: PipelineEvent) {
        (self.0)(event);
    }
}

/// Bounded channel-based event sink
pub struct ChannelEventSink {
    tx: SyncSender<PipelineEvent>,
}

impl ChannelEventSink {
    pub fn new(tx: SyncSender<PipelineEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for ChannelEventSink {
    fn emit(&self, event: PipelineEvent) {
        let _ = self.tx.send(event);
    }
}

/// Create a synchronized streaming event channel
pub fn event_channel(bound: usize) -> (Arc<ChannelEventSink>, Receiver<PipelineEvent>) {
    let (tx, rx) = sync_channel(bound);
    (Arc::new(ChannelEventSink::new(tx)), rx)
}

/// Fan-out multiplexer event sink (broadcasts to multiple sinks)
pub struct MultiEventSink {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl MultiEventSink {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

impl EventSink for MultiEventSink {
    fn emit(&self, event: PipelineEvent) {
        for sink in &self.sinks {
            sink.emit(event.clone());
        }
    }
}

/// Adapter: wraps a legacy `ProgressReporter` as an `EventSink` for backward compatibility
pub struct LegacyProgressAdapter {
    inner: Arc<dyn ProgressReporter>,
}

impl LegacyProgressAdapter {
    pub fn new(inner: Arc<dyn ProgressReporter>) -> Self {
        Self { inner }
    }
}

impl EventSink for LegacyProgressAdapter {
    fn emit(&self, event: PipelineEvent) {
        match event {
            PipelineEvent::Start { total, .. } => {
                self.inner.set_total(total);
            }
            PipelineEvent::FileSuccess { .. } | PipelineEvent::FileSkipped { .. } | PipelineEvent::FileError { .. } => {
                self.inner.increment();
            }
            PipelineEvent::Progress { current, total, .. } => {
                let cur = self.inner.current();
                if current > cur {
                    for _ in 0..(current - cur) {
                        self.inner.increment();
                    }
                }
                if self.inner.total() != total {
                    self.inner.set_total(total);
                }
            }
            _ => {}
        }
    }
}

/// Adapter: wraps an `EventSink` as a `ProgressReporter`
pub struct ProgressReporterSinkAdapter {
    sink: Arc<dyn EventSink>,
    current: AtomicUsize,
    total: AtomicUsize,
}

impl ProgressReporterSinkAdapter {
    pub fn new(sink: Arc<dyn EventSink>) -> Self {
        Self {
            sink,
            current: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
        }
    }
}

impl ProgressReporter for ProgressReporterSinkAdapter {
    fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
        self.sink.emit(PipelineEvent::Start {
            mode: "fix".to_string(),
            total,
            session_time: None,
        });
    }

    fn increment(&self) {
        let cur = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        let tot = self.total.load(Ordering::Relaxed);
        let percent = if tot > 0 {
            (cur as f64 / tot as f64 * 1000.0).round() / 10.0
        } else {
            100.0
        };
        self.sink.emit(PipelineEvent::Progress {
            current: cur,
            total: tot,
            percent,
            status_text: None,
        });
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }

    fn total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_event_serialization() {
        let ev = PipelineEvent::Start {
            mode: "fix".to_string(),
            total: 10,
            session_time: None,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(json, r#"{"event":"start","mode":"fix","total":10}"#);

        let prog = PipelineEvent::Progress {
            current: 5,
            total: 10,
            percent: 50.0,
            status_text: None,
        };
        let json_prog = serde_json::to_string(&prog).unwrap();
        assert_eq!(
            json_prog,
            r#"{"event":"progress","current":5,"total":10,"percent":50.0}"#
        );

        let finish = PipelineEvent::Finish {
            success: true,
            message: "Done".to_string(),
            summary: None,
        };
        let json_finish = serde_json::to_string(&finish).unwrap();
        assert_eq!(json_finish, r#"{"event":"finish","success":true,"message":"Done"}"#);
    }

    #[test]
    fn test_event_channel_stream() {
        let (sink, rx) = event_channel(16);
        sink.emit(PipelineEvent::Start {
            mode: "test".to_string(),
            total: 1,
            session_time: None,
        });
        sink.emit(PipelineEvent::Finish {
            success: true,
            message: "Finished".to_string(),
            summary: None,
        });

        let ev1 = rx.recv().unwrap();
        assert!(matches!(ev1, PipelineEvent::Start { total: 1, .. }));

        let ev2 = rx.recv().unwrap();
        assert!(matches!(ev2, PipelineEvent::Finish { success: true, .. }));
    }
}
