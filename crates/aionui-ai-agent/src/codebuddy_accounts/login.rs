//! Browser-based sign-in for CodeBuddy accounts.
//!
//! The CLI has no `login` subcommand and its interactive TUI needs a keypress
//! before it opens a browser, which is why driving a terminal made the flow
//! look stuck. AionUi talks to the same plugin endpoints the CLI uses instead:
//!
//! 1. `POST /v2/plugin/auth/state?platform=CLI` returns a `state` and the
//!    `authUrl` of the web sign-in page;
//! 2. the system browser opens that URL;
//! 3. `GET /v2/plugin/auth/token?state=…` is polled until the page hands back a
//!    credential (code `11217` means "still waiting");
//! 4. `GET /v2/plugin/account` resolves the uid/nickname for the saved entry.
//!
//! Nothing here writes CodeBuddy's own auth file, so adding an account never
//! replaces the login other CodeBuddy tools are using.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

use super::refresh::{DEFAULT_HOST, RefreshedTokens, http_client, parse_refresh_payload};
use super::{AccountView, CodeBuddyAccountStore, StoredAccount, auth_file};

const PREFIX: &str = "/v2/plugin";
/// Product platform identifier (`product.json` → `"platform": "CLI"`).
const PLATFORM: &str = "CLI";
/// `LOGIN_TOKEN_PENDING_CODE` in the CodeBuddy CLI: the browser has not
/// finished the sign-in yet.
const TOKEN_PENDING_CODE: i64 = 11217;
/// `LOGIN_ACCOUNT_PENDING_CODE`: the token is valid but the profile is still
/// being provisioned.
const ACCOUNT_PENDING_CODE: i64 = 12151;
const POLL_INTERVAL: Duration = Duration::from_millis(1500);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const STATE_TIMEOUT: Duration = Duration::from_secs(8);
const POLL_TIMEOUT: Duration = Duration::from_secs(12);
const ACCOUNT_ATTEMPTS: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginStatus {
    Pending,
    Success,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginSessionView {
    pub session_id: String,
    pub status: LoginStatus,
    pub message: Option<String>,
    pub account: Option<AccountView>,
    /// Sign-in page, so the UI can offer a manual link when the browser did not
    /// open automatically.
    pub auth_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoginStart {
    pub session_id: String,
    pub auth_url: String,
}

struct LoginSession {
    status: LoginStatus,
    message: Option<String>,
    account: Option<StoredAccount>,
    auth_url: Option<String>,
    cancel: Arc<AtomicBool>,
}

/// Tracks in-flight sign-ins. Sessions are process-local and expire with the
/// timeout; a restart simply forgets them.
#[derive(Default)]
pub struct LoginManager {
    sessions: Mutex<HashMap<String, LoginSession>>,
}

impl LoginManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask CodeBuddy for a sign-in page, open it, and start polling for the
    /// resulting credential. Returns once the page exists, not when the user
    /// finishes.
    pub async fn start(self: &Arc<Self>, store: &CodeBuddyAccountStore) -> Result<LoginStart, String> {
        let (host, state, auth_url) = request_auth_state().await?;
        let session_id = uuid::Uuid::new_v4().simple().to_string();
        let cancel = Arc::new(AtomicBool::new(false));

        {
            let mut sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
            sessions.insert(
                session_id.clone(),
                LoginSession {
                    status: LoginStatus::Pending,
                    message: None,
                    account: None,
                    auth_url: Some(auth_url.clone()),
                    cancel: Arc::clone(&cancel),
                },
            );
        }

        open_browser(&auth_url);

        let manager = Arc::clone(self);
        let store = store.clone();
        let session = session_id.clone();
        tokio::spawn(async move {
            manager.poll(store, session, host, state, cancel).await;
        });

        Ok(LoginStart { session_id, auth_url })
    }

    pub fn status(&self, session_id: &str) -> Option<LoginSessionView> {
        let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
        let session = sessions.get(session_id)?;
        Some(LoginSessionView {
            session_id: session_id.to_owned(),
            status: session.status,
            message: session.message.clone(),
            account: session.account.as_ref().map(|account| AccountView {
                id: account.id.clone(),
                name: account.name.clone(),
                uid: account.uid.clone(),
                token_preview: String::new(),
                expires_at: account.expires_at,
                refresh_expires_at: account.refresh_expires_at,
                source: account.source.clone(),
                is_active: false,
                is_expired: false,
                can_refresh: account.refresh_token.as_deref().is_some_and(|token| !token.is_empty()),
                auto_switch_enabled: account.auto_switch_enabled,
                today_credits: 0.0,
            }),
            auth_url: session.auth_url.clone(),
        })
    }

    /// Ask the poll loop to stop. The session is marked failed on the next tick.
    pub fn cancel(&self, session_id: &str) -> bool {
        let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
        match sessions.get(session_id) {
            Some(session) => {
                session.cancel.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    async fn poll(
        &self,
        store: CodeBuddyAccountStore,
        session_id: String,
        host: String,
        state: String,
        cancel: Arc<AtomicBool>,
    ) {
        let started = Instant::now();
        let mut last_error: Option<String> = None;

        loop {
            if cancel.load(Ordering::Relaxed) {
                self.finish(&session_id, LoginStatus::Failed, Some("cancelled".to_owned()), None);
                return;
            }
            if started.elapsed() >= LOGIN_TIMEOUT {
                self.finish(
                    &session_id,
                    LoginStatus::Failed,
                    Some(last_error.unwrap_or_else(|| "sign-in timed out".to_owned())),
                    None,
                );
                return;
            }

            match poll_token(&host, &state).await {
                Ok(Some(tokens)) => {
                    match fetch_account(&host, &tokens.access_token).await {
                        Ok(profile) => {
                            let account = stored_from_login(&store, &profile, tokens, &host);
                            if let Err(error) = store.upsert(account.clone()) {
                                self.finish(
                                    &session_id,
                                    LoginStatus::Failed,
                                    Some(format!("failed to save account: {error}")),
                                    None,
                                );
                            } else {
                                self.finish(&session_id, LoginStatus::Success, None, Some(account));
                            }
                        }
                        Err(error) => {
                            self.finish(&session_id, LoginStatus::Failed, Some(error), None);
                        }
                    }
                    return;
                }
                Ok(None) => {}
                Err(error) => {
                    // Transient network errors are normal while the page is
                    // open; keep polling and surface the last one on timeout.
                    tracing::debug!(%error, "CodeBuddy sign-in poll failed");
                    last_error = Some(error);
                }
            }

            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    fn finish(&self, session_id: &str, status: LoginStatus, message: Option<String>, account: Option<StoredAccount>) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(session) = sessions.get_mut(session_id) {
            session.status = status;
            session.message = message;
            session.account = account;
        }
    }
}

struct AccountProfile {
    uid: String,
    nickname: String,
}

/// Host order: the account's own region (from the live credential), then the
/// global endpoint, then the mainland one. The first that answers wins; the
/// sign-in page it returns already points at the right region.
async fn request_auth_state() -> Result<(String, String, String), String> {
    let mut last_error = String::from("no endpoint tried");
    for host in candidate_hosts() {
        match auth_state_once(&host).await {
            Ok((state, auth_url)) => return Ok((host, state, auth_url)),
            Err(error) => last_error = format!("{host}: {error}"),
        }
    }
    Err(format!("could not start CodeBuddy sign-in ({last_error})"))
}

fn candidate_hosts() -> Vec<String> {
    let mut hosts = Vec::new();
    if let Some(domain) = auth_file::read_current().and_then(|info| info.domain)
        && !domain.is_empty()
    {
        hosts.push(domain);
    }
    for host in [DEFAULT_HOST, "www.codebuddy.cn"] {
        if !hosts.iter().any(|existing| existing == host) {
            hosts.push(host.to_owned());
        }
    }
    hosts
}

async fn auth_state_once(host: &str) -> Result<(String, String), String> {
    let client = http_client(STATE_TIMEOUT)?;
    let response = client
        .post(format!("https://{host}{PREFIX}/auth/state?platform={PLATFORM}"))
        .header("X-Domain", host)
        .header("X-No-Authorization", "true")
        .header("X-No-User-Id", "true")
        .header("X-No-Enterprise-Id", "true")
        .header("X-No-Department-Info", "true")
        .json(&serde_json::json!({}))
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;

    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("invalid response: {error}"))?;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    parse_auth_state(&body, host)
}

fn parse_auth_state(body: &Value, host: &str) -> Result<(String, String), String> {
    if let Some(code) = body.get("code").and_then(Value::as_i64)
        && code != 0
        && code != 200
    {
        return Err(format!("auth state rejected (code={code})"));
    }
    let data = body
        .get("data")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "auth state response has no data".to_owned())?;
    let state = text_field(data, &["state"]).ok_or_else(|| "auth state has no state".to_owned())?;
    let auth_url = text_field(data, &["authUrl", "auth_url"]).ok_or_else(|| "auth state has no URL".to_owned())?;
    // The page is normally absolute; resolve a relative one against the host
    // we just talked to instead of handing the browser a bare path.
    let auth_url = if auth_url.contains("://") {
        auth_url.to_owned()
    } else if auth_url.starts_with('/') {
        format!("https://{host}{auth_url}")
    } else {
        format!("https://{host}/{auth_url}")
    };
    Ok((state.to_owned(), auth_url))
}

async fn poll_token(host: &str, state: &str) -> Result<Option<RefreshedTokens>, String> {
    let client = http_client(POLL_TIMEOUT)?;
    let response = client
        .get(format!("https://{host}{PREFIX}/auth/token?state={state}"))
        .header("X-Domain", host)
        .header("X-No-Authorization", "true")
        .header("X-No-User-Id", "true")
        .header("X-No-Enterprise-Id", "true")
        .header("X-No-Department-Info", "true")
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;

    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("invalid response: {error}"))?;
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let code = body.get("code").and_then(Value::as_i64);
    if code == Some(TOKEN_PENDING_CODE) {
        return Ok(None);
    }
    if let Some(code) = code
        && code != 0
        && code != 200
    {
        let message = body
            .get("message")
            .or_else(|| body.get("msg"))
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!("sign-in rejected (code={code}): {message}"));
    }
    let has_token = body
        .get("data")
        .and_then(|data| data.get("accessToken"))
        .and_then(Value::as_str)
        .is_some_and(|token| !token.is_empty());
    if !has_token {
        return Ok(None);
    }
    parse_refresh_payload(&body, aionui_common::now_ms()).map(Some)
}

/// The token is issued before the profile exists, so retry while CodeBuddy
/// reports `ACCOUNT_PENDING_CODE` (or returns an empty payload).
async fn fetch_account(host: &str, access_token: &str) -> Result<AccountProfile, String> {
    let client = http_client(POLL_TIMEOUT)?;
    let mut last_error = String::from("account profile is not ready");

    for _ in 0..ACCOUNT_ATTEMPTS {
        let response = client
            .get(format!("https://{host}{PREFIX}/account"))
            .header("Authorization", format!("Bearer {access_token}"))
            .header("X-Domain", host)
            .send()
            .await
            .map_err(|error| format!("request failed: {error}"))?;

        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|error| format!("invalid response: {error}"))?;
        if status.is_success() {
            let code = body.get("code").and_then(Value::as_i64);
            if code != Some(ACCOUNT_PENDING_CODE)
                && let Some(data) = body.get("data").filter(|value| !value.is_null())
                && let Some(uid) = account_uid(data)
            {
                let nickname = text_field(data, &["nickname"])
                    .map(str::to_owned)
                    .unwrap_or_else(|| uid.clone());
                return Ok(AccountProfile { uid, nickname });
            }
            if let Some(message) = body.get("message").and_then(Value::as_str) {
                last_error = message.to_owned();
            }
        } else {
            last_error = format!("HTTP {status}");
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }

    Err(format!(
        "signed in but could not read the account profile ({last_error})"
    ))
}

fn account_uid(data: &Value) -> Option<String> {
    text_field(data, &["uid"])
        .or_else(|| data.get("account").and_then(|account| text_field(account, &["uid"])))
        .map(str::to_owned)
}

fn text_field<'a>(data: &'a Value, keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(text) = data.get(*key).and_then(Value::as_str) {
            let text = text.trim();
            if !text.is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn stored_from_login(
    store: &CodeBuddyAccountStore,
    profile: &AccountProfile,
    tokens: RefreshedTokens,
    host: &str,
) -> StoredAccount {
    let now = aionui_common::now_ms();
    StoredAccount {
        id: profile.uid.clone(),
        name: profile.nickname.clone(),
        uid: profile.uid.clone(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        domain: tokens.domain.or_else(|| Some(host.to_owned())),
        token_type: tokens.token_type.unwrap_or_else(|| "Bearer".to_owned()),
        expires_at: tokens.expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
        last_refresh: Some(now),
        profile_dir: store.profile_dir(&profile.uid).to_string_lossy().into_owned(),
        source: "login".to_owned(),
        auto_switch_enabled: true,
        created_at: now,
        last_used_at: 0,
    }
}

fn open_browser(url: &str) {
    // `open` goes through the platform's URL handler (ShellExecute on Windows,
    // `open` on macOS, `xdg-open` elsewhere). Calling `explorer` directly made
    // Windows treat URLs with query strings as filesystem paths and open File
    // Explorer instead of the default browser.
    if let Err(error) = open::that(url) {
        // The UI also shows the URL, so this is not fatal.
        tracing::warn!(%error, "failed to open the CodeBuddy sign-in page");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_none_for_unknown_session() {
        let manager = LoginManager::new();
        assert!(manager.status("missing").is_none());
        assert!(!manager.cancel("missing"));
    }

    #[test]
    fn reads_uid_from_the_flat_or_nested_account_shape() {
        let flat = serde_json::json!({ "uid": "u-1", "nickname": "Unraven" });
        assert_eq!(account_uid(&flat).as_deref(), Some("u-1"));

        let nested = serde_json::json!({ "account": { "uid": "u-2" } });
        assert_eq!(account_uid(&nested).as_deref(), Some("u-2"));

        let empty = serde_json::json!({ "uid": "  " });
        assert!(account_uid(&empty).is_none());
    }

    #[test]
    fn parses_absolute_and_relative_auth_urls() {
        let absolute = serde_json::json!({
            "code": 0,
            "data": { "state": "s-1", "authUrl": "https://www.codebuddy.ai/login?state=s-1" }
        });
        let (state, url) = parse_auth_state(&absolute, "www.codebuddy.ai").expect("state");
        assert_eq!(state, "s-1");
        assert_eq!(url, "https://www.codebuddy.ai/login?state=s-1");

        let relative = serde_json::json!({
            "code": 0,
            "data": { "state": "s-2", "authUrl": "/login?state=s-2" }
        });
        let (_, url) = parse_auth_state(&relative, "www.codebuddy.cn").expect("state");
        assert_eq!(url, "https://www.codebuddy.cn/login?state=s-2");
    }

    #[test]
    fn reports_auth_state_errors() {
        let body = serde_json::json!({ "code": 500, "message": "boom" });
        assert!(parse_auth_state(&body, "www.codebuddy.ai").is_err());

        let empty = serde_json::json!({ "code": 0, "data": {} });
        assert!(parse_auth_state(&empty, "www.codebuddy.ai").is_err());
    }

    #[tokio::test]
    async fn cancel_marks_the_session_as_requested() {
        let manager = Arc::new(LoginManager::new());
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut sessions = manager.sessions.lock().unwrap();
            sessions.insert(
                "sid".to_owned(),
                LoginSession {
                    status: LoginStatus::Pending,
                    message: None,
                    account: None,
                    auth_url: Some("https://example.com".to_owned()),
                    cancel: Arc::clone(&cancel),
                },
            );
        }
        assert!(manager.cancel("sid"));
        assert!(cancel.load(Ordering::Relaxed));
        let view = manager.status("sid").expect("session");
        assert_eq!(view.auth_url.as_deref(), Some("https://example.com"));
    }
}
