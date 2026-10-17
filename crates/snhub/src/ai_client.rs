//! Talking to the language model the operator configured: any OpenAI-compatible
//! chat endpoint (OpenAI, OpenRouter, Nous, LiteLLM, ...)
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
/// OpenAI's newer Responses API (`POST /v1/responses`, "wire_api = responses").
pub const KIND_RESPONSES: &str = "openai_responses";
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
    kind == KIND_OPENAI || kind == KIND_ANTHROPIC || kind == KIND_RESPONSES
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
        KIND_RESPONSES => ("/responses", ""),
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
    let full_already = base.ends_with("/chat/completions")
        || base.ends_with("/responses")
        || base.ends_with("/messages");
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
    } else if kind == KIND_RESPONSES {
        json!({
            "model": model,
            "instructions": system,
            "input": user,
            "stream": false,
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
            "stream": false,
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
    // Either shape is read for either OpenAI-style kind: some gateways answer a
    // `/responses` call in the chat shape (and the other way round), and the
    // operator should not have to know which.
    chat_text(v).or_else(|| responses_text(v))
}

/// `choices[0].message.content` (Chat Completions).
fn chat_text(v: &Value) -> Option<String> {
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

/// `output_text`, or the `output_text` parts of the `message` items in `output`
/// (the Responses API). Reasoning items are not part of the answer.
fn responses_text(v: &Value) -> Option<String> {
    if let Some(s) = v.get("output_text").and_then(Value::as_str)
        && !s.is_empty()
    {
        return Some(s.to_string());
    }
    let mut parts: Vec<&str> = Vec::new();
    for item in v.get("output")?.as_array()? {
        if item.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        for c in item.get("content")?.as_array()? {
            if matches!(
                c.get("type").and_then(Value::as_str),
                Some("output_text" | "text")
            ) && let Some(t) = c.get("text").and_then(Value::as_str)
            {
                parts.push(t);
            }
        }
    }
    (!parts.is_empty()).then(|| parts.join("\n"))
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

/// First characters of a reply, one line, for an error message.
fn snippet(body: &str, max: usize) -> String {
    let one: String = body
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let one = one.split_whitespace().collect::<Vec<_>>().join(" ");
    match one.char_indices().nth(max) {
        Some((i, _)) => format!("{}…", &one[..i]),
        None => one,
    }
}

/// The text one server-sent-events chunk carries, in either provider's shape.
fn chunk_text(v: &Value) -> Option<String> {
    // Responses API: `response.output_text.delta` events carry the answer text.
    if v.get("type").and_then(Value::as_str) == Some("response.output_text.delta") {
        return v.get("delta").and_then(Value::as_str).map(str::to_string);
    }
    // OpenAI: choices[0].delta.content (streaming) or .message.content.
    if let Some(c) = v.get("choices").and_then(|c| c.get(0)) {
        let t = c
            .get("delta")
            .and_then(|d| d.get("content"))
            .or_else(|| c.get("message").and_then(|m| m.get("content")))
            .and_then(Value::as_str)?;
        return Some(t.to_string());
    }
    // Anthropic: delta.text.
    v.get("delta")?.get("text")?.as_str().map(str::to_string)
}

/// Read a reply body into the model's text.
///
/// Accepts a normal JSON reply, and also a server-sent-events stream
/// (`data: {...}` lines) in case a gateway streams although it was asked not to.
/// A JSON error object is reported with its own message.
///
/// # Errors
/// A Vietnamese description of what came back instead, with a hint when it looks
/// like a web page (the usual sign of a wrong URL).
pub fn parse_body(kind: &str, body: &str) -> Result<String, String> {
    let trimmed = body.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        if let Some(t) = reply_text(kind, &v) {
            return Ok(t);
        }
        let why = v
            .get("error")
            .and_then(|e| {
                e.get("message")
                    .and_then(Value::as_str)
                    .or_else(|| e.as_str())
            })
            .or_else(|| v.get("message").and_then(Value::as_str))
            .unwrap_or("không có trường nội dung");
        return Err(format!(
            "máy chủ trả về JSON nhưng không có câu trả lời: {}",
            snippet(why, 200)
        ));
    }
    // A stream: collect the text of every chunk.
    if trimmed.lines().any(|l| l.trim_start().starts_with("data:")) {
        let mut text = String::new();
        for line in trimmed.lines() {
            let Some(d) = line.trim_start().strip_prefix("data:") else {
                continue;
            };
            let d = d.trim();
            if d.is_empty() || d == "[DONE]" {
                continue;
            }
            if let Some(t) = serde_json::from_str::<Value>(d)
                .ok()
                .as_ref()
                .and_then(chunk_text)
            {
                text.push_str(&t);
            }
        }
        if !text.is_empty() {
            return Ok(text);
        }
    }
    let hint = if trimmed.starts_with('<') {
        " Máy chủ trả về một trang web (HTML), thường do endpoint sai hoặc thiếu đường dẫn như /v1."
    } else if trimmed.is_empty() {
        " Phản hồi rỗng."
    } else {
        ""
    };
    Err(format!(
        "phản hồi không phải JSON.{hint} Đầu phản hồi: «{}»",
        snippet(trimmed, 160)
    ))
}

/// Send one exchange to the provider and return the model's text.
///
/// # Errors
/// A Vietnamese message when the endpoint is invalid, the call fails, or the
/// reply has no text. The message names the URL that was called, the HTTP status
/// and the start of what came back, never the key.
pub fn complete(p: &Provider, system: &str, user: &str) -> Result<String> {
    let url = request_url(&p.kind, &p.endpoint)?;
    // No redirects: a POST that is redirected is rarely what the operator meant,
    // and following one would send the Authorization header to another host.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout(TOTAL_TIMEOUT)
        .redirects(0)
        .build();
    let mut req = agent
        .post(&url)
        .set("content-type", "application/json")
        .set("accept", "application/json");
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
        .map_err(|e| anyhow::anyhow!("{} (đã gọi: {url})", describe_error(e, &p.api_key)))?;
    let status = resp.status();
    let content_type = resp.content_type().to_string();
    let location = resp.header("location").unwrap_or("").to_string();
    if (300..400).contains(&status) {
        bail!(
            "endpoint chuyển hướng (HTTP {status}) tới «{}». Hãy nhập địa chỉ đích làm endpoint (đã gọi: {url})",
            snippet(&location, 120)
        );
    }
    let mut text = String::new();
    resp.into_reader()
        .take(MAX_REPLY_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| anyhow::anyhow!("không đọc được phản hồi: {e}"))?;
    match parse_body(&p.kind, &text) {
        Ok(t) => Ok(t),
        Err(why) => {
            let msg = format!("{why} [HTTP {status}, {content_type}; đã gọi: {url}]");
            bail!(
                "{}",
                if p.api_key.len() >= 8 {
                    msg.replace(&p.api_key, "***")
                } else {
                    msg
                }
            )
        }
    }
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
    fn a_normal_json_reply_is_read() {
        let body = r#"{"choices":[{"message":{"content":"OK"}}]}"#;
        assert_eq!(parse_body(KIND_OPENAI, body).unwrap(), "OK");
        let a = r#"{"content":[{"type":"text","text":"hi"}]}"#;
        assert_eq!(parse_body(KIND_ANTHROPIC, a).unwrap(), "hi");
    }

    #[test]
    fn a_stream_is_collected_when_a_gateway_streams_anyway() {
        let sse = "data: {\"choices\":[{\"delta\":{\"content\":\"O\"}}]}\n\n\
                   data: {\"choices\":[{\"delta\":{\"content\":\"K\"}}]}\n\n\
                   data: [DONE]\n";
        assert_eq!(parse_body(KIND_OPENAI, sse).unwrap(), "OK");
        let a = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"Xin\"}}\n\ndata: {\"delta\":{\"text\":\" chao\"}}\n";
        assert_eq!(parse_body(KIND_ANTHROPIC, a).unwrap(), "Xin chao");
    }

    #[test]
    fn a_web_page_is_called_a_web_page_and_the_start_of_it_is_shown() {
        let html = "<!doctype html><html><head><title>Antigravity Manager</title></head><body>...";
        let e = parse_body(KIND_OPENAI, html).unwrap_err();
        assert!(e.contains("HTML") && e.contains("/v1"), "{e}");
        assert!(e.contains("Antigravity Manager"), "{e}");
        assert!(parse_body(KIND_OPENAI, "").unwrap_err().contains("rỗng"));
        let long = "x".repeat(1000);
        let e = parse_body(KIND_OPENAI, &long).unwrap_err();
        assert!(e.chars().count() < 400, "{}", e.chars().count());
    }

    #[test]
    fn a_json_error_object_is_shown_with_its_own_message() {
        let e = parse_body(
            KIND_OPENAI,
            r#"{"error":{"message":"model not found","type":"x"}}"#,
        )
        .unwrap_err();
        assert!(e.contains("model not found"), "{e}");
        let e = parse_body(KIND_OPENAI, r#"{"error":"bad key"}"#).unwrap_err();
        assert!(e.contains("bad key"), "{e}");
        assert!(parse_body(KIND_OPENAI, "{}").is_err());
    }

    #[test]
    fn the_request_asks_for_a_plain_non_streamed_reply() {
        let o = request_body(KIND_OPENAI, "m", "S", "U");
        assert_eq!(o["stream"], false);
    }

    #[test]
    fn the_responses_api_has_its_own_url_body_and_reply_shape() {
        assert_eq!(
            request_url(KIND_RESPONSES, "https://router.sgd.ovh/v1").unwrap(),
            "https://router.sgd.ovh/v1/responses"
        );
        assert_eq!(
            request_url(KIND_RESPONSES, "https://h/v1/responses").unwrap(),
            "https://h/v1/responses"
        );
        let b = request_body(KIND_RESPONSES, "m", "SYS", "USER");
        assert_eq!(
            (b["instructions"].as_str(), b["input"].as_str()),
            (Some("SYS"), Some("USER"))
        );
        assert_eq!(b["stream"], false);
        assert!(b.get("messages").is_none());
        assert!(is_valid_kind("openai_responses"));
        // The reply: output_text, or the text parts of message items (not reasoning).
        let r1 = json!({"output_text": "OK"});
        assert_eq!(reply_text(KIND_RESPONSES, &r1).as_deref(), Some("OK"));
        let r2 = json!({"output":[
            {"type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
            {"type":"message","content":[{"type":"output_text","text":"Xin"},{"type":"output_text","text":"chao"}]}
        ]});
        assert_eq!(
            reply_text(KIND_RESPONSES, &r2).as_deref(),
            Some("Xin\nchao")
        );
        // A gateway that answers /responses in the chat shape is still understood.
        let chat = json!({"choices":[{"message":{"content":"OK."}}]});
        assert_eq!(reply_text(KIND_RESPONSES, &chat).as_deref(), Some("OK."));
        // And the other way round.
        assert_eq!(reply_text(KIND_OPENAI, &r1).as_deref(), Some("OK"));
    }

    #[test]
    fn a_responses_stream_is_collected_from_its_delta_events() {
        let sse = "event: response.created\ndata: {\"type\":\"response.created\"}\n\n\
                   event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"O\"}\n\n\
                   event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"K\"}\n\n\
                   event: response.completed\ndata: {\"type\":\"response.completed\"}\n";
        assert_eq!(parse_body(KIND_RESPONSES, sse).unwrap(), "OK");
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
