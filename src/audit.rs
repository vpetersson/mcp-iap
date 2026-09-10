//! The audit log.
//!
//! Every decision the proxy makes lands here as one JSON object per line. The
//! records are hash-chained: each line commits to the one before it, so a later
//! edit or deletion is detectable with `mcp-iap audit verify`. Bodies are off by
//! default and credential-bearing headers are redacted before anything is written.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use tokio::sync::broadcast;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What happened. `event` names the stage, `decision` names the ACL outcome.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditRecord {
    /// `http` or `mcp`.
    pub kind: String,
    /// `request`, `denied`, `error`, `startup`, `approval`.
    pub event: String,
    pub agent: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    pub target: String,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Anything scheme-specific: redacted headers, truncated bodies, JSON-RPC ids.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl AuditRecord {
    pub fn new(kind: &str, event: &str) -> Self {
        AuditRecord {
            kind: kind.to_string(),
            event: event.to_string(),
            ..Default::default()
        }
    }
}

/// A record once the log has sequenced and chained it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub id: String,
    pub ts: String,
    #[serde(flatten)]
    pub record: AuditRecord,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEvent {
    /// Recompute this entry's hash from its contents and the chain so far.
    fn compute_hash(&self) -> String {
        let mut unhashed = self.clone();
        unhashed.hash = String::new();
        let canonical =
            serde_json::to_string(&unhashed).expect("audit event is always serialisable");
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }

    /// A single line for the TUI feed and for `--stderr` output.
    pub fn oneline(&self) -> String {
        let decision = self
            .record
            .decision
            .as_deref()
            .unwrap_or(&self.record.event);
        let status = self
            .record
            .status
            .map(|s| format!(" {s}"))
            .unwrap_or_default();
        let duration = self
            .record
            .duration_ms
            .map(|d| format!(" {d}ms"))
            .unwrap_or_default();
        format!(
            "[{}] {} {} {} {} {}{}{}",
            decision,
            self.record.agent,
            self.record.kind,
            self.record.target,
            self.record.method,
            self.record.path,
            status,
            duration
        )
    }
}

pub struct AuditLog {
    inner: Mutex<Writer>,
    events: broadcast::Sender<AuditEvent>,
    redact: HashSet<String>,
    max_logged_body_bytes: usize,
    log_bodies: bool,
    log_mcp_params: bool,
    stderr: bool,
}

struct Writer {
    file: BufWriter<File>,
    seq: u64,
    prev_hash: String,
}

impl AuditLog {
    pub fn open(config: &crate::config::AuditConfig, stderr: bool) -> Result<Self> {
        if let Some(parent) = config.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating audit directory `{}`", parent.display()))?;
            }
        }

        // Resume the existing chain so restarts do not break verification.
        let (seq, prev_hash) = match read_tail(&config.path)? {
            Some(last) => (last.seq + 1, last.hash),
            None => (0, GENESIS_HASH.to_string()),
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)
            .with_context(|| format!("opening audit log `{}`", config.path.display()))?;

        let (events, _) = broadcast::channel(512);

        Ok(AuditLog {
            inner: Mutex::new(Writer {
                file: BufWriter::new(file),
                seq,
                prev_hash,
            }),
            events,
            redact: config
                .redact_headers
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            max_logged_body_bytes: config.max_logged_body_bytes,
            log_bodies: config.log_bodies,
            log_mcp_params: config.log_mcp_params,
            stderr,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<AuditEvent> {
        self.events.subscribe()
    }

    pub fn log_bodies(&self) -> bool {
        self.log_bodies
    }

    pub fn log_mcp_params(&self) -> bool {
        self.log_mcp_params
    }

    /// Append a record and return the sequenced event.
    ///
    /// The chain only advances when the line actually reached the file. A failed
    /// write therefore leaves the log verifiable and simply missing that entry —
    /// rather than advancing `seq` past a line that was never written and making
    /// everything after it look tampered with.
    ///
    /// Callers decide what a failure means. On a path that is about to *allow*
    /// something, it should mean refusing: a proxy that cannot record what it
    /// permitted has no business permitting it.
    pub fn write(&self, record: AuditRecord) -> Result<AuditEvent> {
        let mut guard = self.inner.lock();
        let mut event = AuditEvent {
            seq: guard.seq,
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            record,
            prev_hash: guard.prev_hash.clone(),
            hash: String::new(),
        };
        event.hash = event.compute_hash();

        let line = serde_json::to_string(&event).context("serialising an audit event")?;
        writeln!(guard.file, "{line}")
            .and_then(|_| guard.file.flush())
            .inspect_err(|error| tracing::error!(%error, "failed to append to the audit log"))
            .context("appending to the audit log")?;

        guard.seq += 1;
        guard.prev_hash = event.hash.clone();
        drop(guard);

        if self.stderr {
            tracing::info!("{}", event.oneline());
        }
        let _ = self.events.send(event.clone());
        Ok(event)
    }

    /// Append a record where the caller has already decided to refuse, or is
    /// past the point of being able to. Denials and shutdown notes still belong
    /// in the log, but failing to record one must not turn a `deny` into a 500.
    pub fn write_best_effort(&self, record: AuditRecord) -> Option<AuditEvent> {
        match self.write(record) {
            Ok(event) => Some(event),
            Err(error) => {
                tracing::error!(?error, "an audit record was lost");
                None
            }
        }
    }

    /// Replace credential-bearing header values with `***`.
    pub fn redact_headers(&self, headers: &http::HeaderMap) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        for (name, value) in headers {
            let key = name.as_str().to_ascii_lowercase();
            let rendered = if self.redact.contains(&key) {
                "***".to_string()
            } else {
                value.to_str().unwrap_or("<binary>").to_string()
            };
            map.insert(key, serde_json::Value::String(rendered));
        }
        serde_json::Value::Object(map)
    }

    /// Truncate a body to the configured cap, marking that it was cut.
    pub fn clip_body(&self, body: &[u8]) -> serde_json::Value {
        let text = String::from_utf8_lossy(body);
        if text.len() <= self.max_logged_body_bytes {
            serde_json::Value::String(text.into_owned())
        } else {
            let mut end = self.max_logged_body_bytes;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            serde_json::Value::String(format!(
                "{}… <truncated, {} bytes total>",
                &text[..end],
                body.len()
            ))
        }
    }
}

fn read_tail(path: &Path) -> Result<Option<AuditEvent>> {
    if !path.exists() {
        return Ok(None);
    }
    let file =
        File::open(path).with_context(|| format!("opening audit log `{}`", path.display()))?;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        last = Some(
            serde_json::from_str::<AuditEvent>(&line)
                .with_context(|| format!("parsing existing audit log `{}`", path.display()))?,
        );
    }
    Ok(last)
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub first_ts: Option<String>,
    pub last_ts: Option<String>,
}

/// Walk the chain and prove nothing was edited, reordered or removed.
pub fn verify_file(path: &Path) -> Result<VerifyReport> {
    let file =
        File::open(path).with_context(|| format!("opening audit log `{}`", path.display()))?;

    let mut expected_seq = 0u64;
    let mut expected_prev = GENESIS_HASH.to_string();
    let mut entries = 0u64;
    let mut first_ts = None;
    let mut last_ts = None;

    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let line_no = index + 1;
        let event: AuditEvent = serde_json::from_str(&line)
            .with_context(|| format!("line {line_no} is not a valid audit event"))?;

        if event.seq != expected_seq {
            bail!(
                "line {line_no}: sequence gap — expected seq {expected_seq}, found {}",
                event.seq
            );
        }
        if event.prev_hash != expected_prev {
            bail!("line {line_no}: chain break — prev_hash does not match the previous entry");
        }
        if event.compute_hash() != event.hash {
            bail!("line {line_no}: entry was modified after it was written");
        }

        if first_ts.is_none() {
            first_ts = Some(event.ts.clone());
        }
        last_ts = Some(event.ts.clone());
        expected_prev = event.hash;
        expected_seq += 1;
        entries += 1;
    }

    Ok(VerifyReport {
        entries,
        first_ts,
        last_ts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;

    fn log_in(dir: &Path) -> (AuditLog, std::path::PathBuf) {
        let path = dir.join("audit.jsonl");
        let config = AuditConfig {
            path: path.clone(),
            stderr: false,
            ..Default::default()
        };
        (AuditLog::open(&config, false).unwrap(), path)
    }

    #[test]
    fn chain_verifies_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        for index in 0..3 {
            let mut record = AuditRecord::new("http", "request");
            record.agent = format!("agent-{index}");
            log.write(record).unwrap();
        }
        drop(log);

        assert_eq!(verify_file(&path).unwrap().entries, 3);

        // Reopening must continue the chain rather than restart it.
        let (log, _) = log_in(dir.path());
        log.write(AuditRecord::new("mcp", "request")).unwrap();
        drop(log);
        assert_eq!(verify_file(&path).unwrap().entries, 4);
    }

    #[test]
    fn an_edited_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        let mut record = AuditRecord::new("http", "request");
        record.decision = Some("deny".into());
        log.write(record).unwrap();
        log.write(AuditRecord::new("http", "request")).unwrap();
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("\"deny\"", "\"allow\"")).unwrap();

        let err = verify_file(&path).unwrap_err().to_string();
        assert!(err.contains("modified after it was written"), "{err}");
    }

    #[test]
    fn a_removed_entry_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        for _ in 0..3 {
            log.write(AuditRecord::new("http", "request")).unwrap();
        }
        drop(log);

        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, kept.join("\n")).unwrap();

        let err = verify_file(&path).unwrap_err().to_string();
        assert!(err.contains("sequence gap"), "{err}");
    }

    #[test]
    fn a_failed_write_does_not_advance_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let (log, path) = log_in(dir.path());
        log.write(AuditRecord::new("http", "request")).unwrap();

        // Make the next append fail the way a full or read-only disk would.
        {
            let mut guard = log.inner.lock();
            guard.file = BufWriter::new(
                std::fs::OpenOptions::new()
                    .read(true)
                    .open(dir.path().join("audit.jsonl"))
                    .unwrap(),
            );
        }
        assert!(
            log.write(AuditRecord::new("http", "request")).is_err(),
            "an unwritable log must report failure, not swallow it"
        );

        // Restore a working handle and carry on.
        {
            let mut guard = log.inner.lock();
            guard.file = BufWriter::new(
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap(),
            );
        }
        log.write(AuditRecord::new("http", "request")).unwrap();
        drop(log);

        // Two entries reached the file, and the chain over them is intact — the
        // lost record must not leave a gap that reads as tampering.
        let report = verify_file(&path).unwrap();
        assert_eq!(report.entries, 2);
    }

    #[test]
    fn credential_headers_are_redacted() {
        let dir = tempfile::tempdir().unwrap();
        let (log, _) = log_in(dir.path());
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", "Bearer sk-secret".parse().unwrap());
        headers.insert("x-api-key", "sk-ant-secret".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());

        let rendered = log.redact_headers(&headers).to_string();
        assert!(!rendered.contains("sk-secret"), "{rendered}");
        assert!(!rendered.contains("sk-ant-secret"), "{rendered}");
        assert!(rendered.contains("application/json"));
    }

    #[test]
    fn bodies_are_clipped_on_a_char_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(
            &AuditConfig {
                path: dir.path().join("audit.jsonl"),
                stderr: false,
                max_logged_body_bytes: 5,
                ..Default::default()
            },
            false,
        )
        .unwrap();
        let clipped = log.clip_body("aaaaübbbb".as_bytes()).to_string();
        assert!(clipped.contains("truncated"), "{clipped}");
    }
}
