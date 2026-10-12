//! Talking to the language model the operator configured: any OpenAI-compatible
//! chat endpoint (OpenAI, OpenRouter, Nous, vLLM, Ollama's `/v1`, LiteLLM, ...)
//! or Anthropic's Messages API. The operator picks the endpoint, model and key
//! on the settings page; nothing is hard-coded.
//!
//! The request and response shapes are pure functions (tested here). The one
//! network call is bounded in time and in the size it will read, and an error
//! message never contains the key.

use std::io::Read;
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};

pub const KIND_OPENAI: &str = "openai";
pub const KIND_ANTHROPIC: &str = "anthropic";
const ANTHROPIC_DEFAULT: &str = "https://api.anthropic.com";
/// Longest reply read from a model.
const MAX_REPLY_BYTES: u64 = 2 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A model reading a big evidence block can take a while.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, Clone)]
pub struct Provider {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub endpoint: String,
    pub model: String,
    pub api_key: String,
}

#[must_use]
pub fn is_valid_kind(kind: &str) -> bool {
    kind == KIND_OPENAI || kind == KIND_ANTHROPIC
}

/// The full URL to POST to, from what the operator typed. For OpenAI-style
/// providers the base (`https://host/v1`) or the full path both work.
///
/// # Errors
/// When the endpoint is empty (OpenAI-style), has no http(s) scheme, or the kind
/// is unknown.
pub fn request_url(kind: &str, endpoint: &str) -> Result<String> {
    let e = endpoint.trim().trim_end_matches('/');
    let (tail, default) = match kind {
        KIND_OPENAI => ("/chat/completions", ""),
        KIND_ANTHROPIC => ("/v1/messages", ANTHROPIC_DEFAULT),
        _ => bail!("loại provider không hợp lệ"),
    };
    let base = if e.is_empty() { default } else { e };
    if base.is_empty() {
        bail!("cần nhập endpoint");
    }
    if !(base.starts_with("https://") || base.starts_with("http://")) {
        bail!("endpoint phải bắt đầu bằng http:// hoặc https://");
    }
    if base.contains(char::is_whitespace) {
        bail!("endpoint không được chứa khoảng trắng");
    }
    let full_already = base.ends_with("/chat/completions") || base.ends_with("/messages");
    Ok(if full_already {
        base.to_string()
    } else {
        format!("{base}{tail}")
    })
}

/// The JSON body for one system + user exchange.
#[must_use]
pub fn request_body(kind: &str, model: &str, system: &str, user: &str) -> Value {
    if kind == KIND_ANTHROPIC {
        json!({
            "model": model,
            "max_tokens": 4096,
            "system": system,
            "messages": [{ "role": "user", "content": user }],
        })
    } else {
        // Deliberately only the fields every compatible server accepts: some
        // reject `temperature` or `max_tokens` for certain models.
        json!({
            "model": model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
        })
    }
}

/// The reply text from a response body.
#[must_use]
pub fn reply_text(kind: &str, v: &Value) -> Option<String> {
    if kind == KIND_ANTHROPIC {
        let parts: Vec<&str> = v
            .get("content")?
            .as_array()?
            .iter()
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect();
        return (!parts.is_empty()).then(|| parts.join("\n"));
    }
    let content = v.get("choices")?.get(0)?.get("message")?.get("content")?;
    match content {
        Value::String(s) => Some(s.clone()),
        // Some servers return the content as a list of parts.
        Value::Array(parts) => {
            let t: Vec<&str> = parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect();
            (!t.is_empty()).then(|| t.join("\n"))
        }
        _ => None,
    }
}

/// A short, key-free description of a failed call.
fn describe_error(e: ureq::Error, key: &str) -> String {
    let text = match e {
        ureq::Error::Status(code, resp) => {
            let mut body = String::new();
            let _ = resp.into_reader().take(2_000).read_to_string(&mut body);
            let body: String = body.chars().take(240).collect();
            format!("máy chủ AI trả về HTTP {code}: {}", body.replace('\n', " "))
        }
        ureq::Error::Transport(t) => format!("không kết nối được: {t}"),
    };
    // Belt and braces: never let the key travel back into a page or a log.
    if key.len() >= 8 {
        text.replace(key, "***")
    } else {
        text
    }
}

/// Send one exchange to the provider and return the model's text.
///
/// # Errors
/// A Vietnamese message when the endpoint is invalid, the call fails, or the
/// reply has no text.
pub fn complete(p: &Provider, system: &str, user: &str) -> Result<String> {
    let url = request_url(&p.kind, &p.endpoint)?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .build();
    let mut req = agent.post(&url).set("content-type", "application/json");
    if p.kind == KIND_ANTHROPIC {
        req = req
            .set("x-api-key", &p.api_key)
            .set("anthropic-version", "2023-06-01");
    } else if !p.api_key.is_empty() {
        req = req.set("authorization", &format!("Bearer {}", p.api_key));
    }
    let body = request_body(&p.kind, &p.model, system, user);
    let resp = req
        .send_string(&body.to_string())
        .map_err(|e| anyhow::anyhow!(describe_error(e, &p.api_key)))?;
    let mut text = String::new();
    resp.into_reader()
        .take(MAX_REPLY_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| anyhow::anyhow!("không đọc được phản hồi: {e}"))?;
    let v: Value = serde_json::from_str(&text)
        .map_err(|_| anyhow::anyhow!("phản hồi không phải JSON (endpoint có đúng không?)"))?;
    reply_text(&p.kind, &v).ok_or_else(|| anyhow::anyhow!("phản hồi không có nội dung văn bản"))
}

/// `…1234` for display; nothing for a short or empty key.
#[must_use]
pub fn mask_key(key: &str) -> String {
    if key.is_empty() {
        "(chưa nhập)".to_string()
    } else if key.chars().count() <= 8 {
        "••••".to_string()
    } else {
        let tail: String = key
            .chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("••••{tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_style_endpoints_accept_a_base_or_the_full_path() {
        for (given, want) in [
            (
                "https://api.openai.com/v1",
                "https://api.openai.com/v1/chat/completions",
            ),
            (
                "https://api.openai.com/v1/",
                "https://api.openai.com/v1/chat/completions",
            ),
            (
                "https://openrouter.ai/api/v1/chat/completions",
                "https://openrouter.ai/api/v1/chat/completions",
            ),
            (
                "http://127.0.0.1:11434/v1",
                "http://127.0.0.1:11434/v1/chat/completions",
            ),
            (
                "  https://h.example/v1  ",
                "https://h.example/v1/chat/completions",
            ),
        ] {
            assert_eq!(request_url(KIND_OPENAI, given).unwrap(), want, "{given}");
        }
    }

    #[test]
    fn anthropic_defaults_to_its_own_host() {
        assert_eq!(
            request_url(KIND_ANTHROPIC, "").unwrap(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            request_url(KIND_ANTHROPIC, "https://proxy.example/").unwrap(),
            "https://proxy.example/v1/messages"
        );
        assert_eq!(
            request_url(KIND_ANTHROPIC, "https://proxy.example/v1/messages").unwrap(),
            "https://proxy.example/v1/messages"
        );
    }

    #[test]
    fn bad_endpoints_are_refused_with_a_reason() {
        assert!(request_url(KIND_OPENAI, "").is_err());
        assert!(request_url(KIND_OPENAI, "ftp://x").is_err());
        assert!(request_url(KIND_OPENAI, "javascript:alert(1)").is_err());
        assert!(request_url(KIND_OPENAI, "https://a b/v1").is_err());
        assert!(request_url("gemini", "https://x").is_err());
    }

    #[test]
    fn the_request_bodies_have_each_providers_shape() {
        let o = request_body(KIND_OPENAI, "hermes-4", "SYS", "USER");
        assert_eq!(o["model"], "hermes-4");
        assert_eq!(o["messages"][0]["role"], "system");
        assert_eq!(o["messages"][0]["content"], "SYS");
        assert_eq!(o["messages"][1]["role"], "user");
        // Only fields every compatible server takes.
        assert!(o.get("temperature").is_none() && o.get("max_tokens").is_none());

        let a = request_body(KIND_ANTHROPIC, "claude-x", "SYS", "USER");
        assert_eq!(a["system"], "SYS");
        assert_eq!(a["messages"][0]["content"], "USER");
        assert!(a["max_tokens"].as_u64().unwrap() > 0);
    }

    #[test]
    fn the_reply_text_is_found_in_either_shape() {
        let o = json!({"choices":[{"message":{"role":"assistant","content":"OK"}}]});
        assert_eq!(reply_text(KIND_OPENAI, &o).as_deref(), Some("OK"));
        let parts = json!({"choices":[{"message":{"content":[{"type":"text","text":"A"},{"type":"text","text":"B"}]}}]});
        assert_eq!(reply_text(KIND_OPENAI, &parts).as_deref(), Some("A\nB"));
        let a = json!({"content":[{"type":"thinking","thinking":"x"},{"type":"text","text":"hi"}]});
        assert_eq!(reply_text(KIND_ANTHROPIC, &a).as_deref(), Some("hi"));
        for bad in [
            json!({}),
            json!({"choices":[]}),
            json!({"choices":[{"message":{"content":null}}]}),
        ] {
            assert!(reply_text(KIND_OPENAI, &bad).is_none());
        }
        assert!(reply_text(KIND_ANTHROPIC, &json!({"content":[]})).is_none());
    }

    #[test]
    fn keys_are_masked_for_display() {
        assert_eq!(mask_key(""), "(chưa nhập)");
        assert_eq!(mask_key("short"), "••••");
        assert_eq!(mask_key("sk-abcdefghijklmnop1234"), "••••1234");
    }

    #[test]
    fn kinds_are_a_closed_set() {
        assert!(is_valid_kind("openai") && is_valid_kind("anthropic"));
        assert!(!is_valid_kind("") && !is_valid_kind("gemini"));
    }
}
