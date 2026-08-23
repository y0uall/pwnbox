use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use serde::Serialize;
use tokio::sync::Mutex;

/// Collects scan findings (text + JSON). Safe to share across tasks.
#[derive(Clone)]
pub struct Report {
    lines: Arc<Mutex<Vec<String>>>,
    json_data: Arc<Mutex<JsonReport>>,
}

/// JSON report structure for machine-readable output.
#[derive(Clone, Default, Serialize)]
pub struct JsonReport {
    pub box_name: String,
    pub ip: String,
    pub timestamp: String,
    pub os_guess: String,
    pub mode: String,
    pub ports: Vec<PortEntry>,
    pub services: BTreeMap<String, Vec<String>>,
    pub hostnames: Vec<String>,
    pub vulnerabilities: Vec<String>,
    pub next_steps: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct PortEntry {
    pub port: u16,
    pub proto: String,
    pub state: String,
    pub service: String,
    pub version: String,
}

/// Write `content` to a temporary file next to `path`, then atomically rename it.
///
/// This guarantees that `path` is never in a partially-written state: readers
/// either see the old file or the new one, never a truncated intermediate.
async fn write_atomically(path: &Path, content: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    tokio::fs::write(&tmp, content).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

impl Report {
    pub fn new() -> Self {
        Report {
            lines: Arc::new(Mutex::new(Vec::new())),
            json_data: Arc::new(Mutex::new(JsonReport::default())),
        }
    }

    pub async fn add(&self, text: &str) {
        let mut lines = self.lines.lock().await;
        lines.push(text.to_string());
    }

    pub async fn section(&self, title: &str) {
        let mut lines = self.lines.lock().await;
        lines.push(String::new());
        lines.push(format!(
            "\u{2501}\u{2501}\u{2501} {title} \u{2501}\u{2501}\u{2501}"
        ));
    }

    pub async fn write_to_file(&self, path: &Path) -> Result<()> {
        let lines = self.lines.lock().await;
        let content = lines.join("\n");
        write_atomically(path, content.as_bytes()).await
    }

    pub async fn json_mut(&self) -> tokio::sync::MutexGuard<'_, JsonReport> {
        self.json_data.lock().await
    }

    pub async fn write_json(&self, path: &Path) -> Result<()> {
        let data = self.json_data.lock().await;
        let json = serde_json::to_string_pretty(&*data)?;
        write_atomically(path, json.as_bytes()).await
    }

    /// Write the current report state, even if the scan was interrupted.
    ///
    /// This is a semantic alias for `write_to_file`; the write itself is atomic
    /// so a partial write can never leave a corrupt report on disk.
    pub async fn write_partial(&self, path: &Path) -> Result<()> {
        self.write_to_file(path).await
    }

    pub async fn add_port(
        &self,
        port: u16,
        proto: &str,
        state: &str,
        service: &str,
        version: &str,
    ) {
        let mut data = self.json_data.lock().await;
        // one entry per (port, proto) — a re-scan of the same port shouldn't
        // append a second row
        if data
            .ports
            .iter()
            .any(|p| p.port == port && p.proto == proto)
        {
            return;
        }
        data.ports.push(PortEntry {
            port,
            proto: proto.to_string(),
            state: state.to_string(),
            service: service.to_string(),
            version: version.to_string(),
        });
    }

    pub async fn add_service_finding(&self, service: &str, finding: &str) {
        let mut data = self.json_data.lock().await;
        data.services
            .entry(service.to_string())
            .or_default()
            .push(finding.to_string());
    }

    pub async fn add_hostname(&self, hostname: &str) {
        let mut data = self.json_data.lock().await;
        if !data.hostnames.contains(&hostname.to_string()) {
            data.hostnames.push(hostname.to_string());
        }
    }

    pub async fn add_vuln(&self, vuln: &str) {
        let mut data = self.json_data.lock().await;
        // distinct code paths can report the same finding (e.g. Redis flags
        // "unauthenticated access" from more than one branch) — keep it once
        if !data.vulnerabilities.iter().any(|v| v == vuln) {
            data.vulnerabilities.push(vuln.to_string());
        }
    }

    pub async fn add_next_step(&self, step: &str) {
        let mut data = self.json_data.lock().await;
        if !data.next_steps.contains(&step.to_string()) {
            data.next_steps.push(step.to_string());
        }
    }

    /// Record a scanner/tool failure separately from a negative finding.
    pub async fn add_error(&self, component: &str, error: &str) {
        let clean = error.replace(['\r', '\n'], " ");
        let entry = format!("{component}: {clean}");
        let mut data = self.json_data.lock().await;
        if !data.errors.contains(&entry) {
            data.errors.push(entry);
        }
    }

    pub async fn errors(&self) -> Vec<String> {
        self.json_data.lock().await.errors.clone()
    }

    /// Fold another report's contents into this one atomically.
    ///
    /// Concurrent scans each write to their *own* `Report`; we merge those back
    /// into the main report sequentially once the task has joined. That keeps a
    /// section header and its body lines together — they can never be interleaved
    /// with another task's output, which a shared report would allow.
    ///
    /// Only ever called from the main task after the source task has finished, so
    /// the two mutexes are never contended and the lock order can't deadlock.
    pub async fn merge_from(&self, other: &Report) {
        {
            let src = other.lines.lock().await;
            if !src.is_empty() {
                let mut dst = self.lines.lock().await;
                dst.extend(src.iter().cloned());
            }
        }

        let src = other.json_data.lock().await;
        let mut dst = self.json_data.lock().await;
        for p in &src.ports {
            if !dst
                .ports
                .iter()
                .any(|e| e.port == p.port && e.proto == p.proto)
            {
                dst.ports.push(p.clone());
            }
        }
        for (svc, findings) in &src.services {
            dst.services
                .entry(svc.clone())
                .or_default()
                .extend(findings.iter().cloned());
        }
        for h in &src.hostnames {
            if !dst.hostnames.contains(h) {
                dst.hostnames.push(h.clone());
            }
        }
        for v in &src.vulnerabilities {
            if !dst.vulnerabilities.contains(v) {
                dst.vulnerabilities.push(v.clone());
            }
        }
        for step in &src.next_steps {
            if !dst.next_steps.contains(step) {
                dst.next_steps.push(step.clone());
            }
        }
        for error in &src.errors {
            if !dst.errors.contains(error) {
                dst.errors.push(error.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_vuln_dedups_repeated_findings() {
        let r = Report::new();
        r.add_vuln("Redis: unauthenticated access").await;
        r.add_vuln("Redis: unauthenticated access").await;
        assert_eq!(r.json_mut().await.vulnerabilities.len(), 1);
    }

    #[tokio::test]
    async fn add_port_dedups_by_port_and_proto() {
        let r = Report::new();
        r.add_port(80, "tcp", "open", "http", "nginx").await;
        r.add_port(80, "tcp", "open", "http", "nginx 1.24").await; // same port/proto
        r.add_port(80, "udp", "open", "?", "").await; // different proto — kept
        assert_eq!(r.json_mut().await.ports.len(), 2);
    }

    #[tokio::test]
    async fn merge_from_dedups_vulns_and_ports() {
        let a = Report::new();
        a.add_vuln("V1").await;
        a.add_port(22, "tcp", "open", "ssh", "OpenSSH").await;

        let b = Report::new();
        b.add_vuln("V1").await; // duplicate of a
        b.add_vuln("V2").await; // new
        b.add_port(22, "tcp", "open", "ssh", "OpenSSH").await; // duplicate of a

        a.merge_from(&b).await;
        let data = a.json_mut().await;
        assert_eq!(data.vulnerabilities.len(), 2);
        assert_eq!(data.ports.len(), 1);
    }

    #[tokio::test]
    async fn services_are_sorted_alphabetically() {
        let r = Report::new();
        r.add_service_finding("web", "dir: /admin").await;
        r.add_service_finding("ssh", "root login").await;
        r.add_service_finding("web", "title: Login").await;

        let data = r.json_mut().await;
        let keys: Vec<String> = data.services.keys().cloned().collect();
        assert_eq!(keys, vec!["ssh", "web"]);
    }
}
