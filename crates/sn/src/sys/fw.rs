//! nftables backend (`inet sn` table). Bans derived from HTTP traffic only
//! block the web ports, so a false positive never costs SSH, panel, FTP or
//! mail access. The whitelist and the conntrack `established` rule are checked
//! before any ban, so an existing admin session is never dropped.
//!
//! All mutations in a cycle are applied as one `nft -f -` transaction. nft is a
//! documented runtime dependency of watch/enforce (the rescue path degrades to
//! report-only if it is absent).

use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

/// What a set element may be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// One address, or for IPv6 at most a /64 (what one host owns).
    Ban,
    /// Any range the admin configured.
    White,
}

/// A set element rebuilt from its parsed value, and whether it is IPv6.
///
/// Every key passes here before it is written into an nft script, whoever
/// produced it: only an address or a prefix comes out, never text nft would
/// read as a statement of its own.
fn element(key: &str, kind: Kind) -> Result<(String, bool)> {
    let plain = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.' | b'/'));
    let parsed = if plain {
        match key.split_once('/') {
            None => key.parse::<IpAddr>().ok().map(|ip| (ip, None)),
            Some((addr, len)) => addr
                .parse::<IpAddr>()
                .ok()
                .zip(len.parse::<u8>().ok())
                .map(|(ip, len)| (ip, Some(len))),
        }
    } else {
        None
    };
    let Some((ip, len)) = parsed else {
        bail!("refusing firewall key {key:?}: not an address or a prefix");
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let min = match kind {
        Kind::White => 0,
        Kind::Ban if ip.is_ipv4() => 32,
        Kind::Ban => 64,
    };
    match len {
        Some(l) if l < min || l > max => bail!("refusing firewall key {key:?}: prefix /{l}"),
        Some(l) if l < max => Ok((format!("{ip}/{l}"), ip.is_ipv6())),
        _ => Ok((ip.to_string(), ip.is_ipv6())),
    }
}

/// The nft lines for a batch of bans (with per-element timeouts) and of unbans.
fn ban_lines(adds: &[(String, u64)], dels: &[String]) -> Result<(Vec<String>, Vec<String>)> {
    let set = |v6: bool| if v6 { "sn_ban6" } else { "sn_ban4" };
    let mut add_lines = Vec::with_capacity(adds.len());
    for (key, ttl) in adds {
        let (elem, v6) = element(key, Kind::Ban)?;
        if *ttl == 0 {
            // nft reads a 0 timeout as "never expires".
            bail!("refusing a ban of {elem} with no timeout");
        }
        add_lines.push(format!(
            "add element inet sn {} {{ {elem} timeout {ttl}s }}\n",
            set(v6)
        ));
    }
    let mut del_lines = Vec::with_capacity(dels.len());
    for key in dels {
        let (elem, v6) = element(key, Kind::Ban)?;
        del_lines.push(format!("delete element inet sn {} {{ {elem} }}\n", set(v6)));
    }
    Ok((add_lines, del_lines))
}

fn whitelist_script(keys: &[String]) -> Result<String> {
    let mut script = String::from("flush set inet sn sn_white4\nflush set inet sn sn_white6\n");
    for key in keys {
        let (elem, v6) = element(key, Kind::White)?;
        let set = if v6 { "sn_white6" } else { "sn_white4" };
        script.push_str(&format!("add element inet sn {set} {{ {elem} }}\n"));
    }
    Ok(script)
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
    // Every key checked before anything is sent: one bad key stops the batch.
    let (add_lines, del_lines) = ban_lines(adds, dels)?;
    // `delete element` errors if absent, and that aborts the whole transaction,
    // so try the batch and, on failure, fall back to element-by-element best
    // effort.
    let script: String = add_lines
        .iter()
        .chain(&del_lines)
        .map(String::as_str)
        .collect();
    if run_nft_script(&script).is_err() {
        for line in add_lines.iter().chain(&del_lines) {
            let _ = run_nft_script(line);
        }
    }
    Ok(())
}

/// Lift every ban: empty both ban sets (the whitelist and the table stay). A
/// missing table means there is nothing to lift.
pub fn flush_bans() -> Result<()> {
    if run_nft_json(&["list", "table", "inet", "sn"]).is_err() {
        return Ok(());
    }
    run_nft_script(FLUSH_BANS)
}

const FLUSH_BANS: &str = "flush set inet sn sn_ban4\nflush set inet sn sn_ban6\n";

/// Replace the whitelist sets with `keys` (CIDRs or plain addresses).
pub fn set_whitelist(keys: &[String]) -> Result<()> {
    run_nft_script(&whitelist_script(keys)?)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bans(keys: &[&str]) -> Vec<(String, u64)> {
        keys.iter().map(|k| ((*k).to_string(), 3600)).collect()
    }

    #[test]
    fn ban_elements_are_rebuilt_from_the_parsed_address() {
        let (adds, dels) = ban_lines(
            &bans(&["203.0.113.7", "2001:DB8:1:2::/64", "203.0.113.8/32"]),
            &["2001:db8:0:0:0:0:0:1".to_string()],
        )
        .unwrap();
        assert_eq!(
            adds,
            [
                "add element inet sn sn_ban4 { 203.0.113.7 timeout 3600s }\n",
                "add element inet sn sn_ban6 { 2001:db8:1:2::/64 timeout 3600s }\n",
                "add element inet sn sn_ban4 { 203.0.113.8 timeout 3600s }\n",
            ]
        );
        assert_eq!(dels, ["delete element inet sn sn_ban6 { 2001:db8::1 }\n"]);
    }

    #[test]
    fn no_text_but_an_address_gets_into_the_nft_script() {
        for key in [
            "",
            "1.2.3.4 }",
            "1.2.3.4 } ; flush ruleset",
            "1.2.3.4\nadd rule inet sn input accept",
            "2001:db8::/64 }\ndelete table inet sn",
            "1.2.3.4/",
            "/24",
            "1.2.3.4/33",
            "::/129",
            "1.2.3.4/+8",
            "dead:beef::/64x",
            "abc",
        ] {
            assert!(ban_lines(&bans(&[key]), &[]).is_err(), "add {key:?}");
            assert!(ban_lines(&[], &[key.to_string()]).is_err(), "del {key:?}");
            assert!(
                whitelist_script(&[key.to_string()]).is_err(),
                "white {key:?}"
            );
        }
    }

    #[test]
    fn a_ban_is_one_host_never_a_range() {
        for key in ["0.0.0.0/0", "203.0.113.0/24", "::/0", "2001:db8::/48"] {
            assert!(ban_lines(&bans(&[key]), &[]).is_err(), "{key}");
        }
        // A ban with no timeout would never expire.
        assert!(ban_lines(&[("203.0.113.7".to_string(), 0)], &[]).is_err());
    }

    #[test]
    fn one_bad_key_stops_the_whole_batch() {
        assert!(ban_lines(&bans(&["203.0.113.7", "x; flush ruleset"]), &[]).is_err());
    }

    #[test]
    fn the_whitelist_keeps_its_ranges() {
        let s = whitelist_script(&[
            "10.0.0.0/8".to_string(),
            "198.51.100.4".to_string(),
            "2001:db8::/32".to_string(),
        ])
        .unwrap();
        assert!(s.contains("add element inet sn sn_white4 { 10.0.0.0/8 }\n"));
        assert!(s.contains("add element inet sn sn_white4 { 198.51.100.4 }\n"));
        assert!(s.contains("add element inet sn sn_white6 { 2001:db8::/32 }\n"));
        assert_eq!(s.lines().count(), 5);
    }
}
