//! Keep stored CodeBuddy accounts usable without a new browser login.
//!
//! CodeBuddy's CLI treats `CODEBUDDY_AUTH_TOKEN` as a custom token with an
//! empty refresh token (see `CustomTokenAuthenticationStorageImpl` in
//! `@tencent-ai/codebuddy-code`), so an injected session can never renew its
//! own credential. A library entry would therefore stop working as soon as its
//! access token expired. This module renews the token on the host side with the
//! `refreshToken` saved next to it:
//!
//! 1. if CodeBuddy's live auth file belongs to the same account and is newer,
//!    adopt it for free (no network);
//! 2. otherwise, shortly before expiry, call the plugin token-refresh endpoint
//!    and persist the rotated tokens back into the library.
//!
//! The request shape mirrors the plugin's own refresh call: the refresh token
//! travels in `X-Refresh-Token`, the (possibly expired) access token in
//! `Authorization`, and the regional host in `X-Domain`.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::auth_file::{self, AuthFileInfo};
use super::{CodeBuddyAccountStore, StoredAccount};

/// Refresh when the access token is this close to expiry. A full day of runway
/// keeps long sessions alive and still refreshes at most once per token cycle.
const REFRESH_AHEAD_MS: i64 = 24 * 60 * 60 * 1000;
/// Also renew when the refresh token itself is about to expire: that is the
/// last chance to extend the account without a browser sign-in.
const REFRESH_TOKEN_AHEAD_MS: i64 = 7 * 24 * 60 * 60 * 1000;
pub(super) const DEFAULT_HOST: &str = "www.codebuddy.ai";
const REFRESH_PATH: &str = "/v2/plugin/auth/token/refresh";
const REFRESH_TIMEOUT_SECS: u64 = 15;
/// Values below this are seconds, above are milliseconds (year ~5138 in s).
const SECONDS_THRESHOLD: i64 = 100_000_000_000;

/// Shared HTTP client for the CodeBuddy endpoints. Built per call: these are
/// rare control-plane requests, not a hot path.
pub(super) fn http_client(timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|error| format!("cannot build HTTP client: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshedTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub token_type: Option<String>,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
    pub domain: Option<String>,
}

/// Whether the account's access token is expired or about to expire.
pub fn needs_refresh(account: &StoredAccount, now: i64) -> bool {
    let access_due = account
        .expires_at
        .is_some_and(|expires_at| expires_at - now <= REFRESH_AHEAD_MS);
    let refresh_due = account
        .refresh_expires_at
        .is_some_and(|expires_at| expires_at - now <= REFRESH_TOKEN_AHEAD_MS);
    access_due || refresh_due
}

/// Outcome of a proactive renewal sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RefreshSummary {
    pub refreshed: usize,
    pub failed: usize,
}

/// Renew every account that is close to either token's expiry.
///
/// Used by the settings panel and the background alert hook so an idle app
/// still rotates tokens before they die. Accounts without a refresh token, or
/// whose refresh token is already rejected, are reported as failed instead of
/// aborting the sweep.
pub async fn refresh_expiring(store: &CodeBuddyAccountStore) -> RefreshSummary {
    let now = aionui_common::now_ms();
    let accounts = store.list().0;
    let mut summary = RefreshSummary::default();

    for account in accounts {
        if !needs_refresh(&account, now) {
            continue;
        }
        let before_access = account.access_token.clone();
        let before_expires = account.expires_at;
        let before_refresh_expires = account.refresh_expires_at;
        let before_last_refresh = account.last_refresh;
        let updated = ensure_fresh(store, account).await;
        let changed = updated.access_token != before_access
            || updated.expires_at != before_expires
            || updated.refresh_expires_at != before_refresh_expires
            || updated.last_refresh != before_last_refresh;
        if changed {
            summary.refreshed += 1;
        } else {
            summary.failed += 1;
        }
    }

    summary
}

/// Return an account whose token is valid, refreshing it when possible.
///
/// Never fails: a network or refresh-token error leaves the stored account
/// untouched, so the session still starts with the old token (and surfaces the
/// usual auth error if that token is really dead).
pub async fn ensure_fresh(store: &CodeBuddyAccountStore, account: StoredAccount) -> StoredAccount {
    let account = adopt_live_credentials(store, account);
    if !needs_refresh(&account, aionui_common::now_ms()) {
        return account;
    }
    if account.refresh_token.as_deref().is_none_or(str::is_empty) {
        tracing::debug!(
            account = %account.name,
            "CodeBuddy token expired but no refresh token is stored; re-import the account to enable renewal"
        );
        return account;
    }

    match request_refresh(&account).await {
        Ok(tokens) => {
            let now = aionui_common::now_ms();
            let updated = StoredAccount {
                access_token: tokens.access_token,
                refresh_token: tokens.refresh_token.or_else(|| account.refresh_token.clone()),
                domain: tokens.domain.or_else(|| account.domain.clone()),
                token_type: tokens.token_type.unwrap_or_else(|| account.token_type.clone()),
                expires_at: tokens.expires_at.or(account.expires_at),
                refresh_expires_at: tokens.refresh_expires_at.or(account.refresh_expires_at),
                last_refresh: Some(now),
                ..account
            };
            if let Err(error) = store.upsert(updated.clone()) {
                tracing::warn!(account = %updated.name, %error, "failed to persist refreshed CodeBuddy token");
            }
            // If this account is also CodeBuddy's own live login, keep that
            // file in sync: the refresh may have rotated the refresh token, and
            // CodeBuddy would otherwise be left holding a dead one.
            if let Some(live) = auth_file::read_current()
                && live.uid == updated.uid
                && !live.has_timestamp_suffix
                && let Err(error) = auth_file::write_live_tokens(
                    &live.path,
                    &updated.access_token,
                    updated.refresh_token.as_deref(),
                    updated.expires_at,
                    updated.refresh_expires_at,
                    now,
                )
            {
                tracing::warn!(
                    account = %updated.name,
                    %error,
                    "failed to write refreshed CodeBuddy token back to the live auth file"
                );
            }
            updated
        }
        Err(error) => {
            tracing::warn!(
                account = %account.name,
                %error,
                "CodeBuddy token refresh failed; keeping the stored token"
            );
            account
        }
    }
}

/// Adopt credentials CodeBuddy itself refreshed, when the live login is the
/// same account. Also backfills `refresh_token` for libraries written before
/// refresh tokens were stored.
pub fn adopt_live_for_current(store: &CodeBuddyAccountStore) {
    let Some(live) = auth_file::read_current() else {
        return;
    };
    let Some(account) = store.list().0.into_iter().find(|account| account.uid == live.uid) else {
        return;
    };
    adopt_with_live(store, account, &live);
}

/// Backfill refresh tokens for entries saved before this module existed.
///
/// CodeBuddy keeps a timestamped `.info` for every account it has ever logged
/// into on this machine, and those backups contain the refresh token. Copying
/// the newest one per uid makes existing libraries renewable without asking the
/// user to import everything again.
pub fn backfill_from_history(store: &CodeBuddyAccountStore) {
    let (accounts, _) = store.list();
    if accounts
        .iter()
        .all(|account| account.refresh_token.as_deref().is_some_and(|token| !token.is_empty()))
    {
        return;
    }
    let infos = auth_file::scan_history();
    for account in accounts {
        if account.refresh_token.as_deref().is_some_and(|token| !token.is_empty()) {
            continue;
        }
        let Some(info) = infos.iter().find(|info| info.uid == account.uid) else {
            continue;
        };
        let Some(updated) = merge_live(info, &account) else {
            continue;
        };
        if let Err(error) = store.upsert(updated.clone()) {
            tracing::warn!(account = %updated.name, %error, "failed to backfill CodeBuddy refresh token");
        }
    }
}

fn adopt_live_credentials(store: &CodeBuddyAccountStore, account: StoredAccount) -> StoredAccount {
    match auth_file::read_current() {
        Some(live) => adopt_with_live(store, account, &live),
        None => account,
    }
}

fn adopt_with_live(store: &CodeBuddyAccountStore, account: StoredAccount, live: &AuthFileInfo) -> StoredAccount {
    let Some(updated) = merge_live(live, &account) else {
        return account;
    };
    if let Err(error) = store.upsert(updated.clone()) {
        tracing::warn!(account = %updated.name, %error, "failed to persist credentials refreshed by CodeBuddy");
    }
    updated
}

/// Pure merge used by [`adopt_live_credentials`]. Returns `None` when the live
/// credential is older than the stored one and nothing can be backfilled.
fn merge_live(live: &AuthFileInfo, account: &StoredAccount) -> Option<StoredAccount> {
    if live.uid != account.uid {
        return None;
    }
    let mut updated = account.clone();
    let mut changed = false;

    if live.expires_at.unwrap_or(0) > account.expires_at.unwrap_or(0) {
        updated.access_token = live.access_token.clone();
        updated.expires_at = live.expires_at;
        updated.refresh_expires_at = live.refresh_expires_at.or(account.refresh_expires_at);
        updated.token_type = live.token_type.clone();
        // A newer credential usually rotated the refresh token with it.
        if live.refresh_token.is_some() {
            updated.refresh_token = live.refresh_token.clone();
        }
        changed = true;
    }
    if updated.refresh_token.as_deref().is_none_or(str::is_empty) && live.refresh_token.is_some() {
        updated.refresh_token = live.refresh_token.clone();
        changed = true;
    }
    if updated.domain.is_none() && live.domain.is_some() {
        updated.domain = live.domain.clone();
        changed = true;
    }
    if changed {
        updated.last_refresh = account.last_refresh.max(live.last_refresh);
        Some(updated)
    } else {
        None
    }
}

async fn request_refresh(account: &StoredAccount) -> Result<RefreshedTokens, String> {
    let refresh_token = account
        .refresh_token
        .as_deref()
        .filter(|token| !token.is_empty())
        .ok_or_else(|| "account has no refresh token".to_owned())?;
    let domain = account.domain.as_deref();
    let host = domain
        .filter(|host| !host.is_empty() && !host.contains('/'))
        .unwrap_or(DEFAULT_HOST);
    let url = format!("https://{host}{REFRESH_PATH}");

    let client = http_client(Duration::from_secs(REFRESH_TIMEOUT_SECS))?;

    let mut request = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", account.access_token))
        .header("X-Refresh-Token", refresh_token)
        .header("X-Auth-Refresh-Source", "plugin")
        // The endpoint is built for plugin/browser traffic; a bare reqwest UA
        // is the odd one out.
        .header(
            reqwest::header::USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
        );
    if let Some(domain) = domain {
        request = request.header("X-Domain", domain);
    }

    let response = request
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(format!("refresh token rejected (HTTP {status})"));
    }
    if !status.is_success() {
        return Err(format!("refresh failed (HTTP {status})"));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("invalid refresh response: {error}"))?;
    parse_refresh_payload(&body, aionui_common::now_ms())
}

pub(super) fn parse_refresh_payload(body: &Value, now: i64) -> Result<RefreshedTokens, String> {
    if let Some(code) = body.get("code").and_then(value_i64)
        && code != 0
        && code != 200
    {
        let message = body
            .get("message")
            .or_else(|| body.get("msg"))
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return Err(format!("refresh rejected (code={code}): {message}"));
    }
    let data = body
        .get("data")
        .filter(|value| !value.is_null())
        .ok_or_else(|| "refresh response has no data".to_owned())?;
    let access_token = text_field(data, &["accessToken", "access_token"])
        .ok_or_else(|| "refresh response has no access token".to_owned())?;

    Ok(RefreshedTokens {
        access_token: access_token.to_owned(),
        refresh_token: text_field(data, &["refreshToken", "refresh_token"]).map(str::to_owned),
        token_type: text_field(data, &["tokenType", "token_type"]).map(str::to_owned),
        expires_at: expiry_at(data, &["expiresAt", "expires_at"], &["expiresIn", "expires_in"], now),
        refresh_expires_at: expiry_at(
            data,
            &["refreshExpiresAt", "refresh_expires_at"],
            &["refreshExpiresIn", "refresh_expires_in"],
            now,
        ),
        domain: text_field(data, &["domain"]).map(str::to_owned),
    })
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

/// Absolute expiry in ms, falling back to a relative `expiresIn` (seconds).
/// Each slot accepts both camelCase and snake_case spellings.
fn expiry_at(data: &Value, absolute_keys: &[&str], relative_keys: &[&str], now: i64) -> Option<i64> {
    if let Some(value) = first_i64(data, absolute_keys) {
        return Some(if value < SECONDS_THRESHOLD { value * 1000 } else { value });
    }
    first_i64(data, relative_keys)
        .filter(|seconds| *seconds > 0)
        .map(|seconds| now + seconds * 1000)
}

fn first_i64(data: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|key| data.get(*key).and_then(value_i64))
}

fn value_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(expires_at: Option<i64>) -> StoredAccount {
        StoredAccount {
            id: "uid-1".into(),
            name: "Unraven".into(),
            uid: "uid-1".into(),
            access_token: "access-old".into(),
            refresh_token: Some("refresh-old".into()),
            domain: Some("www.codebuddy.cn".into()),
            token_type: "Bearer".into(),
            expires_at,
            refresh_expires_at: None,
            last_refresh: Some(1_000),
            profile_dir: String::new(),
            source: "import".into(),
            auto_switch_enabled: true,
            created_at: 0,
            last_used_at: 0,
        }
    }

    fn live(expires_at: i64) -> AuthFileInfo {
        AuthFileInfo {
            path: std::path::PathBuf::new(),
            uid: "uid-1".into(),
            nickname: "Unraven".into(),
            access_token: "access-live".into(),
            refresh_token: Some("refresh-live".into()),
            domain: Some("www.codebuddy.cn".into()),
            token_type: "Bearer".into(),
            expires_at: Some(expires_at),
            refresh_expires_at: Some(expires_at + 1000),
            last_refresh: Some(2_000),
            has_timestamp_suffix: false,
        }
    }

    #[test]
    fn refreshes_only_when_close_to_expiry() {
        let now = 1_000_000_000_000;
        assert!(!needs_refresh(&stored(Some(now + 2 * REFRESH_AHEAD_MS)), now));
        assert!(needs_refresh(&stored(Some(now + REFRESH_AHEAD_MS / 2)), now));
        assert!(needs_refresh(&stored(Some(now - 1)), now));
        // Unknown expiry is left alone.
        assert!(!needs_refresh(&stored(None), now));
    }

    #[test]
    fn renews_before_the_refresh_token_expires_even_when_the_access_token_is_fine() {
        let now = 1_000_000_000_000;
        let mut account = stored(Some(now + 30 * 24 * 60 * 60 * 1000));
        account.refresh_expires_at = Some(now + REFRESH_TOKEN_AHEAD_MS / 2);
        assert!(needs_refresh(&account, now));

        account.refresh_expires_at = Some(now + 30 * 24 * 60 * 60 * 1000);
        assert!(!needs_refresh(&account, now));
    }

    #[test]
    fn adopts_a_newer_live_credential() {
        let account = stored(Some(1_000));
        let merged = merge_live(&live(5_000), &account).expect("merge");
        assert_eq!(merged.access_token, "access-live");
        assert_eq!(merged.refresh_token.as_deref(), Some("refresh-live"));
        assert_eq!(merged.expires_at, Some(5_000));
        assert_eq!(merged.last_refresh, Some(2_000));
    }

    #[test]
    fn ignores_an_older_live_credential() {
        let account = stored(Some(5_000));
        assert!(merge_live(&live(1_000), &account).is_none());
    }

    #[test]
    fn backfills_a_missing_refresh_token_from_the_live_file() {
        let mut account = stored(Some(5_000));
        account.refresh_token = None;
        let merged = merge_live(&live(1_000), &account).expect("merge");
        assert_eq!(merged.access_token, "access-old");
        assert_eq!(merged.refresh_token.as_deref(), Some("refresh-live"));
    }

    #[test]
    fn ignores_a_live_credential_for_another_account() {
        let mut other = live(5_000);
        other.uid = "uid-2".into();
        assert!(merge_live(&other, &stored(Some(1_000))).is_none());
    }

    #[test]
    fn parses_camel_case_payload_with_millisecond_expiry() {
        let body = serde_json::json!({
            "code": 0,
            "data": {
                "accessToken": "access-new",
                "refreshToken": "refresh-new",
                "tokenType": "Bearer",
                "expiresAt": 1_800_000_000_000_i64,
                "refreshExpiresAt": 1_800_100_000_000_i64,
                "domain": "www.codebuddy.cn"
            }
        });
        let tokens = parse_refresh_payload(&body, 0).expect("parse");
        assert_eq!(tokens.access_token, "access-new");
        assert_eq!(tokens.refresh_token.as_deref(), Some("refresh-new"));
        assert_eq!(tokens.expires_at, Some(1_800_000_000_000));
    }

    #[test]
    fn parses_snake_case_payload_with_relative_expiry() {
        let body = serde_json::json!({
            "code": 200,
            "data": {
                "access_token": "access-new",
                "expires_in": 3600,
                "refresh_expires_in": "7200"
            }
        });
        let tokens = parse_refresh_payload(&body, 1_000).expect("parse");
        assert_eq!(tokens.access_token, "access-new");
        assert_eq!(tokens.expires_at, Some(1_000 + 3_600_000));
        assert_eq!(tokens.refresh_expires_at, Some(1_000 + 7_200_000));
    }

    #[test]
    fn parses_second_based_absolute_expiry() {
        let body = serde_json::json!({
            "code": 0,
            "data": { "accessToken": "a", "expiresAt": 1_800_000_000_i64 }
        });
        let tokens = parse_refresh_payload(&body, 0).expect("parse");
        assert_eq!(tokens.expires_at, Some(1_800_000_000_000));
    }

    #[test]
    fn reports_business_errors() {
        let body = serde_json::json!({ "code": 401, "message": "token expired" });
        let error = parse_refresh_payload(&body, 0).expect_err("error");
        assert!(error.contains("401"));
        assert!(error.contains("token expired"));
    }

    #[test]
    fn rejects_payloads_without_data() {
        let body = serde_json::json!({ "code": 0 });
        assert!(parse_refresh_payload(&body, 0).is_err());
    }
}
