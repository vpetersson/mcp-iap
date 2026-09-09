//! Interactive approval — the Little Snitch part.
//!
//! An `ask` verdict parks the request here and blocks it until a human answers
//! in the TUI (or over the control API). Nothing is ever allowed by default:
//! a timeout, or having no approver attached at all, denies.

use indexmap::IndexMap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::acl::AccessRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

/// How a parked request was ultimately resolved — recorded verbatim in the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// A human answered.
    Decided(Verdict),
    /// A "remember for this session" answer given earlier applied.
    Remembered(Verdict),
    /// Nobody answered in time.
    TimedOut,
    /// Nothing is watching the queue, so there is no one to answer.
    NoApprover,
}

impl Outcome {
    pub fn verdict(self) -> Verdict {
        match self {
            Outcome::Decided(v) | Outcome::Remembered(v) => v,
            // Fail closed.
            Outcome::TimedOut | Outcome::NoApprover => Verdict::Deny,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Decided(Verdict::Allow) => "ask:allowed",
            Outcome::Decided(Verdict::Deny) => "ask:denied",
            Outcome::Remembered(Verdict::Allow) => "ask:allowed-remembered",
            Outcome::Remembered(Verdict::Deny) => "ask:denied-remembered",
            Outcome::TimedOut => "ask:timeout-denied",
            Outcome::NoApprover => "ask:no-approver-denied",
        }
    }
}

/// What the TUI and the control API see for one parked request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingView {
    pub id: String,
    pub request: AccessRequest,
    pub summary: String,
    pub waited_ms: u64,
    pub agent_name: String,
}

struct Pending {
    request: AccessRequest,
    agent_name: String,
    created: Instant,
    responder: oneshot::Sender<Verdict>,
}

/// How long a control-plane poll counts as someone still watching the queue.
/// Long enough for a human tailing it with `curl`, short enough that a
/// forgotten shell does not keep requests parked for the full timeout.
const APPROVER_POLL_TTL: Duration = Duration::from_secs(30);

pub struct ApprovalBroker {
    pending: Mutex<IndexMap<String, Pending>>,
    /// "…and remember for this session" answers, keyed by the exact access request.
    remembered: Mutex<HashMap<String, Verdict>>,
    console_attached: AtomicBool,
    last_poll: Mutex<Option<Instant>>,
    changes: broadcast::Sender<()>,
    timeout: Duration,
}

impl ApprovalBroker {
    pub fn new(timeout: Duration) -> Self {
        let (changes, _) = broadcast::channel(64);
        ApprovalBroker {
            pending: Mutex::new(IndexMap::new()),
            remembered: Mutex::new(HashMap::new()),
            console_attached: AtomicBool::new(false),
            last_poll: Mutex::new(None),
            changes,
            timeout,
        }
    }

    /// Declare that the interactive console is running.
    pub fn set_has_approver(&self, value: bool) {
        self.console_attached.store(value, Ordering::SeqCst);
    }

    /// Someone read the queue over the control plane; they can answer for a while.
    pub fn note_poll(&self) {
        *self.last_poll.lock() = Some(Instant::now());
    }

    /// Is anyone actually in a position to answer? If not, `ask` must not park a
    /// request for the full timeout — it should deny immediately.
    pub fn has_approver(&self) -> bool {
        self.console_attached.load(Ordering::SeqCst)
            || self
                .last_poll
                .lock()
                .is_some_and(|at| at.elapsed() < APPROVER_POLL_TTL)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.changes.subscribe()
    }

    /// Park a request until a human answers, a remembered answer applies, or we time out.
    pub async fn ask(&self, request: &AccessRequest, agent_name: &str) -> Outcome {
        if let Some(verdict) = self.remembered.lock().get(&request.session_key()).copied() {
            return Outcome::Remembered(verdict);
        }
        if !self.has_approver() {
            return Outcome::NoApprover;
        }

        let id = Uuid::new_v4().to_string();
        let (responder, receiver) = oneshot::channel();
        self.pending.lock().insert(
            id.clone(),
            Pending {
                request: request.clone(),
                agent_name: agent_name.to_string(),
                created: Instant::now(),
                responder,
            },
        );
        let _ = self.changes.send(());

        let outcome = match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(verdict)) => Outcome::Decided(verdict),
            // Sender dropped: the queue was cleared out from under us. Fail closed.
            Ok(Err(_)) => Outcome::TimedOut,
            Err(_) => Outcome::TimedOut,
        };

        self.pending.lock().shift_remove(&id);
        let _ = self.changes.send(());
        outcome
    }

    pub fn list(&self) -> Vec<PendingView> {
        let guard = self.pending.lock();
        guard
            .iter()
            .map(|(id, pending)| PendingView {
                id: id.clone(),
                summary: pending.request.summary(),
                request: pending.request.clone(),
                waited_ms: pending.created.elapsed().as_millis() as u64,
                agent_name: pending.agent_name.clone(),
            })
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }

    /// Answer one parked request. `remember` applies the same answer to identical
    /// requests for as long as this process runs.
    pub fn decide(&self, id: &str, verdict: Verdict, remember: bool) -> bool {
        let Some(pending) = self.pending.lock().shift_remove(id) else {
            return false;
        };
        if remember {
            self.remembered
                .lock()
                .insert(pending.request.session_key(), verdict);
        }
        let delivered = pending.responder.send(verdict).is_ok();
        let _ = self.changes.send(());
        delivered
    }

    /// Answer the request that has been waiting longest — the TUI's default target.
    pub fn decide_first(&self, verdict: Verdict, remember: bool) -> bool {
        let id = self.pending.lock().keys().next().cloned();
        match id {
            Some(id) => self.decide(&id, verdict, remember),
            None => false,
        }
    }

    pub fn remembered_count(&self) -> usize {
        self.remembered.lock().len()
    }

    pub fn forget_all(&self) {
        self.remembered.lock().clear();
        let _ = self.changes.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn request() -> AccessRequest {
        AccessRequest::http("claude", "gh", "POST", "/repos/x/issues")
    }

    #[tokio::test]
    async fn denies_when_nothing_is_watching_the_queue() {
        let broker = ApprovalBroker::new(Duration::from_secs(5));
        let outcome = broker.ask(&request(), "Claude").await;
        assert_eq!(outcome, Outcome::NoApprover);
        assert_eq!(outcome.verdict(), Verdict::Deny);
    }

    #[tokio::test]
    async fn polling_the_queue_counts_as_watching_it_for_a_while() {
        let broker = ApprovalBroker::new(Duration::from_secs(5));
        assert!(!broker.has_approver());
        broker.note_poll();
        assert!(
            broker.has_approver(),
            "a fresh poll means someone can answer"
        );
    }

    #[tokio::test]
    async fn a_human_allow_releases_the_request() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5)));
        broker.set_has_approver(true);

        let asker = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.ask(&request(), "Claude").await })
        };

        // Wait for it to appear in the queue, then answer it.
        let id = loop {
            if let Some(view) = broker.list().into_iter().next() {
                break view.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert!(broker.decide(&id, Verdict::Allow, false));

        assert_eq!(asker.await.unwrap(), Outcome::Decided(Verdict::Allow));
        assert_eq!(broker.pending_count(), 0);
    }

    #[tokio::test]
    async fn remembering_short_circuits_the_next_identical_request() {
        let broker = Arc::new(ApprovalBroker::new(Duration::from_secs(5)));
        broker.set_has_approver(true);

        let asker = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move { broker.ask(&request(), "Claude").await })
        };
        let id = loop {
            if let Some(view) = broker.list().into_iter().next() {
                break view.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        broker.decide(&id, Verdict::Allow, true);
        asker.await.unwrap();

        // Same request again: answered from memory, without parking.
        assert_eq!(
            broker.ask(&request(), "Claude").await,
            Outcome::Remembered(Verdict::Allow)
        );
        // A different path is a different decision and must be asked again.
        let other = AccessRequest::http("claude", "gh", "DELETE", "/repos/x");
        broker.set_has_approver(false);
        assert_eq!(broker.ask(&other, "Claude").await, Outcome::NoApprover);

        broker.forget_all();
        assert_eq!(broker.remembered_count(), 0);
    }

    #[tokio::test]
    async fn an_unanswered_request_times_out_denied() {
        let broker = ApprovalBroker::new(Duration::from_millis(40));
        broker.set_has_approver(true);
        let outcome = broker.ask(&request(), "Claude").await;
        assert_eq!(outcome, Outcome::TimedOut);
        assert_eq!(outcome.verdict(), Verdict::Deny);
        assert_eq!(
            broker.pending_count(),
            0,
            "timed-out requests must be reaped"
        );
    }
}
