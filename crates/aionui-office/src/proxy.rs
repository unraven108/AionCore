use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use reqwest::header::{CONTENT_TYPE, HOST, HeaderMap, HeaderName, HeaderValue};

use crate::types::DocType;
use crate::watch_manager::OfficecliWatchManager;

const PROXY_TIMEOUT: Duration = Duration::from_secs(30);

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "cookie",
    "authorization",
];

const NAVIGATION_GUARD_TEMPLATE: &str = r#"<script>
(function(b){
function rw(u){if(!u)return u;var s=String(u);var m=/^https?:\/\/(?:localhost|127\.0\.0\.1)(:\d+)?(\/.*)?$/.exec(s);if(m){var p=m[2]||'/';if(!p.startsWith(b))return b+(p==='/'?'/':p);}if(s==='/'||(s[0]==='/'&&s[1]!=='/'&&!s.startsWith(b)))return b+(s==='/'?'/':s);return s;}
var _a=location.assign.bind(location),_r=location.replace.bind(location);
location.assign=function(u){_a(rw(u));};location.replace=function(u){_r(rw(u));};
var _ps=history.pushState.bind(history),_rs=history.replaceState.bind(history);
history.pushState=function(s,t,u){_ps(s,t,u?rw(u):u);};history.replaceState=function(s,t,u){_rs(s,t,u?rw(u):u);};
try{Object.defineProperty(location,'href',{set:function(v){_a(rw(v));},configurable:true});}catch(e){}
document.addEventListener('click',function(e){var t=e.target;while(t&&t.tagName!=='A')t=t.parentElement;if(t&&t.tagName==='A'){var h=t.getAttribute('href');if(h&&(h[0]==='/'&&h[1]!=='/'&&!h.startsWith(b))){e.preventDefault();_a(b+h);}}},true);
/* Request-scoped URLs need the same treatment, and EventSource matters most:
   the watch page opens its update stream at the root-absolute '/events', which
   without rewriting resolves against the app origin and 404s — the preview then
   never receives a single update and stays on whatever it painted first. */
var _ES=window.EventSource;
if(_ES){var ES=function(u,c){return new _ES(rw(u),c);};ES.prototype=_ES.prototype;ES.CONNECTING=_ES.CONNECTING;ES.OPEN=_ES.OPEN;ES.CLOSED=_ES.CLOSED;window.EventSource=ES;}
var _fe=window.fetch;
if(_fe){window.fetch=function(i,o){var u=i;if(typeof i==='string'){u=rw(i);}else if(typeof Request!=='undefined'&&i instanceof Request){u=new Request(rw(i.url),i);}return _fe(u,o);};}
var _xo=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u){var a=[].slice.call(arguments);if(typeof u==='string'){a[1]=rw(u);}return _xo.apply(this,a);};
})('PROXY_BASE_PLACEHOLDER');
</script>"#;

/// Markers officecli's watch page renders when its *first* render failed.
///
/// The page then waits for a document update to replace it, and officecli only
/// re-renders on its own edits (external ones are explicitly not detected), so
/// nothing ever replaces it. Both markers are required: a real document could
/// plausibly contain the first sentence, but not the pair, so this cannot turn
/// "the document happens to say this" into a spurious failure. If officecli ever
/// rewords the page the check degrades to "assume rendered" — the old behaviour —
/// rather than to a false error.
const WATCH_PLACEHOLDER_MARKERS: [&str; 2] = [
    "Waiting for first update",
    "Run an officecli command to see the preview",
];

pub struct ProxyService {
    watch_manager: Arc<OfficecliWatchManager>,
    client: reqwest::Client,
    /// Client for streaming responses (the watcher's `/events` feed).
    ///
    /// `client`'s whole-response timeout would kill an endless SSE body after
    /// 30s, so streams get their own client: no total timeout, only a bound on
    /// connecting.
    stream_client: reqwest::Client,
}

#[derive(Debug)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A proxied response whose body is still arriving.
pub struct ProxyStreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: futures_util::stream::BoxStream<'static, Result<axum::body::Bytes, std::io::Error>>,
}

// The body is a stream, which is not `Debug`; the status and headers are what a
// caller can usefully print.
impl std::fmt::Debug for ProxyStreamResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyStreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body", &"<stream>")
            .finish()
    }
}

/// What the watch page currently shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderState {
    /// The document itself.
    Rendered,
    /// officecli's "waiting for the first update" page: the first render failed
    /// and nothing will retry it.
    Placeholder,
    /// The page could not be read; nothing can be concluded from that.
    Unknown,
}

impl ProxyService {
    pub fn new(watch_manager: Arc<OfficecliWatchManager>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(PROXY_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build proxy HTTP client");

        let stream_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build streaming proxy HTTP client");

        Self {
            watch_manager,
            client,
            stream_client,
        }
    }

    /// Tell the watch server on `port` to re-render `absolute_path`, by re-issuing
    /// the switch it already holds.
    ///
    /// officecli has no same-file short-circuit here on purpose — it documents a
    /// repeat switch as a force-refresh — so this re-renders from disk and then
    /// broadcasts `doc-switched`, which the embedded page reacts to by reloading.
    /// Nothing is streamed back to our caller; the reload happens between officecli
    /// and the webview.
    ///
    /// Deliberately not routed through [`forward`](Self::forward): that path is a
    /// read-only GET proxy for page assets. This is a control call with a body, and
    /// its failures map to codes the frontend already has copy for rather than being
    /// relayed as an HTTP response.
    ///
    /// `Err` carries a stable code. Every failure is safe to show as "refresh did
    /// not happen": officecli keeps serving the current document when a switch
    /// fails, so the tab the user is looking at survives.
    pub(crate) async fn force_reload(
        &self,
        port: u16,
        absolute_path: &str,
        timeout: std::time::Duration,
    ) -> Result<(), &'static str> {
        let url = build_target_url(port, "/api/switch");
        let result = self
            .client
            .post(&url)
            .timeout(timeout)
            .json(&serde_json::json!({ "file": absolute_path }))
            .send()
            .await;

        let response = match result {
            Ok(response) => response,
            Err(err) => {
                // The path is ours, not the client's, so it stays in the log.
                tracing::warn!(target: "office_refresh", port, error = %err, "switch request failed");
                return Err(if err.is_timeout() {
                    "OFFICECLI_PORT_TIMEOUT"
                } else {
                    "OFFICECLI_START_FAILED"
                });
            }
        };

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        // officecli's documented rejections. 409 means another process holds the
        // per-file update pipe — distinct from a render failure, because the
        // document is fine and the conflict is about who serves it.
        let code = match status.as_u16() {
            404 => "OFFICECLI_FILE_NOT_FOUND",
            409 => "OFFICECLI_ALREADY_WATCHED",
            400 => "OFFICECLI_UNSUPPORTED_FILE",
            _ => "OFFICECLI_START_FAILED",
        };
        tracing::warn!(target: "office_refresh", port, status = status.as_u16(), code, "switch rejected");
        Err(code)
    }

    pub async fn forward(
        &self,
        port: u16,
        path: &str,
        doc_type: DocType,
        request_headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        self.forward_for_user("system_default_user", port, path, doc_type, request_headers)
            .await
    }

    pub async fn forward_for_user(
        &self,
        user_id: &str,
        port: u16,
        path: &str,
        doc_type: DocType,
        request_headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        if !self.watch_manager.is_active_port_for_user(user_id, port, doc_type) {
            return Err(ProxyError::PortNotActive(port));
        }
        let proxy_base = format!("/api/{}/{}", doc_type.proxy_prefix(), port);
        self.forward_inner(port, path, &proxy_base, request_headers).await
    }

    pub async fn forward_watch(
        &self,
        port: u16,
        path: &str,
        request_headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        self.forward_watch_for_user("system_default_user", port, path, request_headers)
            .await
    }

    pub async fn forward_watch_for_user(
        &self,
        user_id: &str,
        port: u16,
        path: &str,
        request_headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        if !self.watch_manager.is_active_watch_port_for_user(user_id, port) {
            return Err(ProxyError::PortNotActive(port));
        }
        let proxy_base = format!("/api/office-watch-proxy/{port}");
        self.forward_inner(port, path, &proxy_base, request_headers).await
    }

    /// Ask the watch server on `port` what it is currently showing.
    ///
    /// Used right after a preview starts: officecli answers `GET /` from its cache,
    /// so a placeholder page here means the first render failed and nothing will
    /// retry it. `Unknown` (unreachable, unreadable body) deliberately does not
    /// count as a failure — the caller only acts on `Placeholder`.
    pub async fn render_state(&self, port: u16) -> RenderState {
        let url = build_target_url(port, "/");
        let response = match self.client.get(&url).send().await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(port, %error, "could not read watch page state");
                return RenderState::Unknown;
            }
        };

        if !response.status().is_success() {
            tracing::warn!(
                port,
                status = response.status().as_u16(),
                "watch page returned an error"
            );
            return RenderState::Unknown;
        }

        match response.text().await {
            Ok(body) if WATCH_PLACEHOLDER_MARKERS.iter().all(|marker| body.contains(marker)) => {
                RenderState::Placeholder
            }
            Ok(_) => RenderState::Rendered,
            Err(error) => {
                tracing::warn!(port, %error, "could not read watch page body");
                RenderState::Unknown
            }
        }
    }

    /// Proxy a response whose body keeps arriving — the watcher's `/events` feed.
    ///
    /// The buffered [`forward`](Self::forward) path cannot carry this: it waits for
    /// a complete body with a 30s budget, so an SSE stream would either time out or
    /// arrive as one late lump, and the page would connect, hang, and reconnect
    /// forever. Nothing is rewritten here — event streams carry no HTML.
    pub async fn forward_event_stream_for_user(
        &self,
        user_id: &str,
        port: u16,
        path: &str,
        doc_type: DocType,
        request_headers: &[(String, String)],
    ) -> Result<ProxyStreamResponse, ProxyError> {
        if !self.watch_manager.is_active_port_for_user(user_id, port, doc_type) {
            return Err(ProxyError::PortNotActive(port));
        }
        let proxy_base = format!("/api/{}/{}", doc_type.proxy_prefix(), port);
        self.forward_stream_inner(port, path, &proxy_base, request_headers)
            .await
    }

    /// Streaming variant of [`forward_watch`](Self::forward_watch): the
    /// office-watch proxy serves both Word and Excel sessions, so the port check
    /// accepts either.
    pub async fn forward_watch_event_stream_for_user(
        &self,
        user_id: &str,
        port: u16,
        path: &str,
        request_headers: &[(String, String)],
    ) -> Result<ProxyStreamResponse, ProxyError> {
        if !self.watch_manager.is_active_watch_port_for_user(user_id, port) {
            return Err(ProxyError::PortNotActive(port));
        }
        let proxy_base = format!("/api/office-watch-proxy/{port}");
        self.forward_stream_inner(port, path, &proxy_base, request_headers)
            .await
    }

    async fn forward_stream_inner(
        &self,
        port: u16,
        path: &str,
        proxy_base: &str,
        request_headers: &[(String, String)],
    ) -> Result<ProxyStreamResponse, ProxyError> {
        let target_url = build_target_url(port, path);
        let req_headers = build_upstream_headers(port, request_headers);

        let resp = self
            .stream_client
            .get(&target_url)
            .headers(req_headers)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ProxyError::Timeout
                } else if e.is_connect() {
                    ProxyError::ConnectionFailed(e.to_string())
                } else {
                    ProxyError::RequestFailed(e.to_string())
                }
            })?;

        let status = resp.status().as_u16();
        let headers = collect_out_headers(resp.headers(), false, port, proxy_base);

        let body = resp
            .bytes_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other))
            .boxed();

        Ok(ProxyStreamResponse { status, headers, body })
    }

    async fn forward_inner(
        &self,
        port: u16,
        path: &str,
        proxy_base: &str,
        request_headers: &[(String, String)],
    ) -> Result<ProxyResponse, ProxyError> {
        let target_url = build_target_url(port, path);
        let req_headers = build_upstream_headers(port, request_headers);

        let resp = self
            .client
            .get(&target_url)
            .headers(req_headers)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    ProxyError::Timeout
                } else if e.is_connect() {
                    ProxyError::ConnectionFailed(e.to_string())
                } else {
                    ProxyError::RequestFailed(e.to_string())
                }
            })?;

        let status = resp.status().as_u16();
        let resp_headers = resp.headers().clone();
        let body = resp
            .bytes()
            .await
            .map_err(|e| ProxyError::RequestFailed(format!("failed to read response body: {e}")))?;

        let is_html = is_html_content_type(&resp_headers);
        let out_headers = collect_out_headers(&resp_headers, is_html, port, proxy_base);
        let mut body_bytes = body.to_vec();

        if is_html {
            body_bytes = inject_navigation_guard(&body_bytes, proxy_base);
        }

        Ok(ProxyResponse {
            status,
            headers: out_headers,
            body: body_bytes,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("port {0} is not an active preview port")]
    PortNotActive(u16),

    #[error("proxy request timed out")]
    Timeout,

    #[error("connection to preview server failed: {0}")]
    ConnectionFailed(String),

    #[error("proxy request failed: {0}")]
    RequestFailed(String),
}

fn build_target_url(port: u16, path: &str) -> String {
    let normalized = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    format!("http://127.0.0.1:{port}{normalized}")
}

/// Copy the caller's headers upstream, minus the ones that must not travel: the
/// connection-scoped set, and `Host`, which has to name the watch server.
fn build_upstream_headers(port: u16, request_headers: &[(String, String)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HOST,
        HeaderValue::from_str(&format!("127.0.0.1:{port}")).unwrap_or_else(|_| HeaderValue::from_static("127.0.0.1")),
    );

    for (key, value) in request_headers {
        let lower = key.to_lowercase();
        if is_hop_by_hop(&lower) || lower == "host" {
            continue;
        }
        if let (Ok(name), Ok(val)) = (HeaderName::from_bytes(lower.as_bytes()), HeaderValue::from_str(value)) {
            headers.insert(name, val);
        }
    }

    headers
}

fn is_hop_by_hop(header: &str) -> bool {
    HOP_BY_HOP_HEADERS.contains(&header)
}

/// Map upstream headers onto the response we hand back, dropping hop-by-hop
/// headers, rewriting redirects into the proxy's namespace, and stamping the
/// framing policy the preview panels rely on.
fn collect_out_headers(resp_headers: &HeaderMap, is_html: bool, port: u16, proxy_base: &str) -> Vec<(String, String)> {
    let mut out_headers = Vec::new();

    for (name, value) in resp_headers.iter() {
        let name_str = name.as_str().to_lowercase();

        if is_hop_by_hop(&name_str) {
            continue;
        }

        if name_str == "location"
            && let Ok(loc) = value.to_str()
        {
            let rewritten = rewrite_location(loc, port, proxy_base);
            out_headers.push(("location".to_owned(), rewritten));
            continue;
        }

        // An injected guard changes the length; a streamed body has none at all.
        if is_html && name_str == "content-length" {
            continue;
        }

        if let Ok(val_str) = value.to_str() {
            out_headers.push((name_str, val_str.to_owned()));
        }
    }

    out_headers.push(("x-frame-options".to_owned(), "SAMEORIGIN".to_owned()));
    out_headers
}

fn is_html_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/html"))
}

fn rewrite_location(location: &str, port: u16, proxy_base: &str) -> String {
    let pattern = format!("http://localhost:{port}");
    let pattern_ip = format!("http://127.0.0.1:{port}");

    let rewritten = if location.starts_with(&pattern) {
        format!("{proxy_base}{}", &location[pattern.len()..])
    } else if location.starts_with(&pattern_ip) {
        format!("{proxy_base}{}", &location[pattern_ip.len()..])
    } else {
        location.to_owned()
    };

    if rewritten == "/"
        || (rewritten.starts_with('/') && !rewritten.starts_with("//") && !rewritten.starts_with(proxy_base))
    {
        if rewritten == "/" {
            format!("{proxy_base}/")
        } else {
            format!("{proxy_base}{rewritten}")
        }
    } else {
        rewritten
    }
}

fn inject_navigation_guard(body: &[u8], proxy_base: &str) -> Vec<u8> {
    let html = String::from_utf8_lossy(body);
    let guard_script = NAVIGATION_GUARD_TEMPLATE.replace("PROXY_BASE_PLACEHOLDER", proxy_base);

    let result = if let Some(pos) = find_head_tag_end(&html) {
        format!("{}{}{}", &html[..pos], guard_script, &html[pos..])
    } else {
        format!("{guard_script}{html}")
    };

    result.into_bytes()
}

fn find_head_tag_end(html: &str) -> Option<usize> {
    let lower = html.to_lowercase();
    let head_start = lower.find("<head")?;
    let tag_end = lower[head_start..].find('>')?;
    Some(head_start + tag_end + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_target_url_with_leading_slash() {
        assert_eq!(
            build_target_url(8080, "/index.html"),
            "http://127.0.0.1:8080/index.html"
        );
    }

    #[test]
    fn build_target_url_without_leading_slash() {
        assert_eq!(build_target_url(8080, "index.html"), "http://127.0.0.1:8080/index.html");
    }

    #[test]
    fn build_target_url_root() {
        assert_eq!(build_target_url(3000, "/"), "http://127.0.0.1:3000/");
    }

    #[test]
    fn build_target_url_empty_path() {
        assert_eq!(build_target_url(3000, ""), "http://127.0.0.1:3000/");
    }

    #[test]
    fn is_hop_by_hop_recognizes_all_headers() {
        for h in HOP_BY_HOP_HEADERS {
            assert!(is_hop_by_hop(h), "expected {h} to be hop-by-hop");
        }
    }

    #[test]
    fn is_hop_by_hop_rejects_normal_headers() {
        assert!(!is_hop_by_hop("content-type"));
        assert!(!is_hop_by_hop("accept"));
        assert!(!is_hop_by_hop("x-custom-header"));
    }

    #[test]
    fn is_html_content_type_detects_html() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        assert!(is_html_content_type(&headers));
    }

    #[test]
    fn is_html_content_type_rejects_json() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        assert!(!is_html_content_type(&headers));
    }

    #[test]
    fn is_html_content_type_empty_headers() {
        let headers = HeaderMap::new();
        assert!(!is_html_content_type(&headers));
    }

    #[test]
    fn rewrite_location_localhost_absolute() {
        let result = rewrite_location("http://localhost:8080/new/path", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "/api/ppt-proxy/8080/new/path");
    }

    #[test]
    fn rewrite_location_ip_absolute() {
        let result = rewrite_location("http://127.0.0.1:8080/new/path", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "/api/ppt-proxy/8080/new/path");
    }

    #[test]
    fn rewrite_location_root_relative() {
        let result = rewrite_location("/foo/bar", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "/api/ppt-proxy/8080/foo/bar");
    }

    #[test]
    fn rewrite_location_root_path() {
        let result = rewrite_location("/", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "/api/ppt-proxy/8080/");
    }

    #[test]
    fn rewrite_location_already_proxied() {
        let result = rewrite_location("/api/ppt-proxy/8080/existing", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "/api/ppt-proxy/8080/existing");
    }

    #[test]
    fn rewrite_location_external_url_unchanged() {
        let result = rewrite_location("https://example.com/path", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "https://example.com/path");
    }

    #[test]
    fn rewrite_location_different_port_unchanged() {
        let result = rewrite_location("http://localhost:9999/path", 8080, "/api/ppt-proxy/8080");
        assert_eq!(result, "http://localhost:9999/path");
    }

    #[test]
    fn rewrite_location_localhost_root() {
        let result = rewrite_location("http://localhost:3000", 3000, "/api/office-watch-proxy/3000");
        assert_eq!(result, "/api/office-watch-proxy/3000");
    }

    #[test]
    fn inject_guard_with_head_tag() {
        let html = b"<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>";
        let result = inject_navigation_guard(html, "/api/ppt-proxy/8080");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("<head><script>"));
        assert!(result_str.contains("'/api/ppt-proxy/8080'"));
        assert!(result_str.contains("<title>Test</title>"));
    }

    #[test]
    fn inject_guard_with_head_attributes() {
        let html = b"<html><head lang=\"en\"><title>Test</title></head></html>";
        let result = inject_navigation_guard(html, "/api/ppt-proxy/8080");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("lang=\"en\"><script>"));
    }

    #[test]
    fn inject_guard_no_head_tag() {
        let html = b"<html><body>content</body></html>";
        let result = inject_navigation_guard(html, "/api/ppt-proxy/8080");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.starts_with("<script>"));
        assert!(result_str.contains("content</body>"));
    }

    #[test]
    fn inject_guard_uppercase_head() {
        let html = b"<HTML><HEAD><TITLE>Test</TITLE></HEAD></HTML>";
        let result = inject_navigation_guard(html, "/api/ppt-proxy/8080");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("<HEAD><script>"));
    }

    #[test]
    fn find_head_tag_end_normal() {
        assert_eq!(find_head_tag_end("<html><head><title>"), Some(12));
    }

    #[test]
    fn find_head_tag_end_with_attrs() {
        let html = "<html><head lang=\"en\">";
        assert_eq!(find_head_tag_end(html), Some(html.len()));
    }

    #[test]
    fn find_head_tag_end_uppercase() {
        assert_eq!(find_head_tag_end("<html><HEAD>"), Some(12));
    }

    #[test]
    fn find_head_tag_end_missing() {
        assert_eq!(find_head_tag_end("<html><body>"), None);
    }

    #[test]
    fn proxy_error_display() {
        assert_eq!(
            ProxyError::PortNotActive(8080).to_string(),
            "port 8080 is not an active preview port"
        );
        assert_eq!(ProxyError::Timeout.to_string(), "proxy request timed out");
        assert_eq!(
            ProxyError::ConnectionFailed("refused".into()).to_string(),
            "connection to preview server failed: refused"
        );
    }

    #[test]
    fn navigation_guard_contains_all_intercepts() {
        let guard = NAVIGATION_GUARD_TEMPLATE;
        assert!(guard.contains("location.assign"));
        assert!(guard.contains("location.replace"));
        assert!(guard.contains("history.pushState"));
        assert!(guard.contains("history.replaceState"));
        assert!(guard.contains("location,'href'"));
        assert!(guard.contains("addEventListener('click'"));
    }

    // The watch page opens `/events` with a root-absolute path. Without these
    // rewrites the stream resolves against the app origin, 404s, and the preview
    // never receives another update.
    #[test]
    fn navigation_guard_rewrites_request_urls() {
        let guard = NAVIGATION_GUARD_TEMPLATE;
        assert!(guard.contains("window.EventSource"), "EventSource must be wrapped");
        assert!(guard.contains("XMLHttpRequest.prototype.open"), "XHR must be wrapped");
        assert!(guard.contains("window.fetch"), "fetch must be wrapped");
    }
}
