//! nftables backend (`inet sn` table). Bans derived from HTTP traffic only
//! block the web ports, so a false positive never costs SSH, panel, FTP or
//! mail access. The whitelist and the conntrack `established` rule are checked
//! before any ban, so an existing admin session is never dropped.
//!
//! All mutations in a cycle are applied as one `nft -f -` transaction. nft is a
//! documented runtime dependency of watch/enforce (the rescue path degrades to
//! report-only if it is absent).

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// True if a key is IPv6 (contains a colon). Both plain and `/prefix` forms.
fn is_v6(key: &str) -> bool {
    key.contains(':')
}

fn run_nft_script(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning nft (is nftables installed?)")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(script.as_bytes())
        .context("writing nft script")?;
    let out = child.wait_with_output().context("waiting for nft")?;
    if !out.status.success() {
        bail!(
            "nft failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn run_nft_json(args: &[&str]) -> Result<serde_json::Value> {
    let out = Command::new("nft")
        .arg("-j")
        .args(args)
        .output()
        .context("spawning nft -j")?;
    if !out.status.success() {
        bail!(
            "nft -j failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).context("parsing nft json")?;
    Ok(v)
}

/// Is nft available on this host?
#[must_use]
pub fn available() -> bool {
    Command::new("nft")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create (idempotently) the `inet sn` table, sets and input chain. Existing
/// ban/white set contents are preserved — only the chain's rules are rebuilt.
pub fn ensure_table(web_ports: &[u16]) -> Result<()> {
    let ports = web_ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let script = format!(
        r#"add table inet sn
add set inet sn sn_ban4 {{ type ipv4_addr; flags timeout; }}
add set inet sn sn_ban6 {{ type ipv6_addr; flags interval, timeout; }}
add set inet sn sn_white4 {{ type ipv4_addr; flags interval; }}
add set inet sn sn_white6 {{ type ipv6_addr; flags interval; }}
add chain inet sn input {{ type filter hook input priority -10; policy accept; }}
flush chain inet sn input
add rule inet sn input ct state established,related accept
add rule inet sn input iif "lo" accept
add rule inet sn input ip saddr @sn_white4 accept
add rule inet sn input ip6 saddr @sn_white6 accept
add rule inet sn input ip saddr @sn_ban4 tcp dport {{ {ports} }} drop
add rule inet sn input ip6 saddr @sn_ban6 tcp dport {{ {ports} }} drop
"#
    );
    run_nft_script(&script)
}

/// Apply a batch of bans (add with per-element timeout) and unbans in one
/// transaction. `adds` are `(key, ttl_secs)`.
pub fn apply_bans(adds: &[(String, u64)], dels: &[String]) -> Result<()> {
    if adds.is_empty() && dels.is_empty() {
        return Ok(());
    }
    let mut script = String::new();
    for (key, ttl) in adds {
        let set = if is_v6(key) { "sn_ban6" } else { "sn_ban4" };
        script.push_str(&format!(
            "add element inet sn {set} {{ {key} timeout {ttl}s }}\n"
        ));
    }
    for key in dels {
        let set = if is_v6(key) { "sn_ban6" } else { "sn_ban4" };
        // `delete element` errors if absent; guard each in its own best-effort
        // line by tolerating failure at the caller — here we batch and ignore
        // individual misses by issuing them separately.
        script.push_str(&format!("delete element inet sn {set} {{ {key} }}\n"));
    }
    // Deletes of absent elements abort the whole transaction, so try the batch
    // and, on failure, fall back to element-by-element best effort.
    if run_nft_script(&script).is_err() {
        for (key, ttl) in adds {
            let set = if is_v6(key) { "sn_ban6" } else { "sn_ban4" };
            let _ = run_nft_script(&format!(
                "add element inet sn {set} {{ {key} timeout {ttl}s }}\n"
            ));
        }
        for key in dels {
            let set = if is_v6(key) { "sn_ban6" } else { "sn_ban4" };
            let _ = run_nft_script(&format!("delete element inet sn {set} {{ {key} }}\n"));
        }
    }
    Ok(())
}

/// Replace the whitelist sets with `keys` (CIDRs or plain addresses).
pub fn set_whitelist(keys: &[String]) -> Result<()> {
    let mut script = String::from("flush set inet sn sn_white4\nflush set inet sn sn_white6\n");
    for key in keys {
        let set = if is_v6(key) { "sn_white6" } else { "sn_white4" };
        script.push_str(&format!("add element inet sn {set} {{ {key} }}\n"));
    }
    run_nft_script(&script)
}

/// Read the current ban keys from both sets.
pub fn list_ban_keys() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for set in ["sn_ban4", "sn_ban6"] {
        let v = match run_nft_json(&["list", "set", "inet", "sn", set]) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(arr) = v.get("nftables").and_then(|n| n.as_array()) {
            for item in arr {
                if let Some(elems) = item
                    .get("set")
                    .and_then(|s| s.get("elem"))
                    .and_then(|e| e.as_array())
                {
                    for e in elems {
                        collect_elem_key(e, &mut out);
                    }
                }
            }
        }
    }
    Ok(out)
}

fn collect_elem_key(e: &serde_json::Value, out: &mut Vec<String>) {
    // elem is either "1.2.3.4" or { "elem": { "val": ..., "timeout": .. } }
    match e {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Object(_) => {
            if let Some(val) = e.get("elem").and_then(|x| x.get("val")) {
                match val {
                    serde_json::Value::String(s) => out.push(s.clone()),
                    serde_json::Value::Object(_) => {
                        // prefix form { "prefix": { "addr": .., "len": .. } }
                        if let Some(pfx) = val.get("prefix")
                            && let (Some(addr), Some(len)) = (
                                pfx.get("addr").and_then(|a| a.as_str()),
                                pfx.get("len").and_then(|l| l.as_u64()),
                            )
                        {
                            out.push(format!("{addr}/{len}"));
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

/// Remove the whole `inet sn` table (used by `sn disable` / kill switch).
pub fn delete_table() -> Result<()> {
    run_nft_script("delete table inet sn\n")
}
