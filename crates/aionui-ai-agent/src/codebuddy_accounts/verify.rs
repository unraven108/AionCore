//! Check whether a stored CodeBuddy credential still works.
//!
//! A local expiry timestamp only proves what the token file claimed when it
//! was written; the server may have revoked or rotated it since. Verification
//! therefore refreshes near-expiry credentials first and then asks the same
//! plugin endpoint the sign-in flow uses (`GET /v2/plugin/account`) for the
//! profile behind the token. A profile whose uid matches the stored account is
//! the strongest local proof that the account can start a session.

use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use super::refresh::{DEFAULT_HOST, http_client};
use super::{CodeBuddyAccountStore, ensure_fresh};

const VERIFY_PATH: &str = "/v2/plugin/account";
const VERIFY_TIMEOUT_SECS: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyStatus {
    Valid,
    Invalid,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyResult {
    pub status: VerifyStatus,
    pub message: Option<String>,
    pub checked_at: i64,
}

/// Verify one account. `Err` means the account id itself was not found; every
/// other outcome is reported in [`VerifyResult`] so the UI can show it.
pub async fn verify_account(store: &CodeBuddyAccountStore, id: &str) -> Result<VerifyResult, String> {
    let account = store
        .list()
        .0
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| format!("account '{id}' not found"))?;

    // Renew first: an expired access token is exactly what the button is
    // meant to repair when a refresh token is still good.
    let account = ensure_fresh(store, account).await;
    let now = aionui_common::now_ms();
    if account.expires_at.is_some_and(|expires_at| expires_at <= now) {
        return Ok(VerifyResult {
            status: VerifyStatus::Invalid,
            message: Some("access token expired and automatic renewal failed".to_owned()),
            checked_at: now,
        });
    }

    let host = account
        .domain
        .as_deref()
        .filter(|host| !host.is_empty() && !host.contains('/'))
        .unwrap_or(DEFAULT_HOST);
    let client = http_client(Duration::from_secs(VERIFY_TIMEOUT_SECS))?;
    let response = client
        .get(format!("https://{host}{VERIFY_PATH}"))
        .header("Authorization", format!("Bearer {}", account.access_token))
        .header("X-Domain", host)
        .send()
        .await
        .map_err(|error| format!("request failed: {error}"))?;

    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    Ok(classify_account_response(status, &body, &account.uid, now))
}

/// Pure response classifier so the network-free cases stay testable.
fn classify_account_response(status: u16, body: &Value, expected_uid: &str, checked_at: i64) -> VerifyResult {
    if status == 401 || status == 403 {
        return invalid("the token was rejected by CodeBuddy", checked_at);
    }
    if !(200..300).contains(&status) {
        return VerifyResult {
            status: VerifyStatus::Error,
            message: Some(format!("CodeBuddy returned HTTP {status}")),
            checked_at,
        };
    }

    if let Some(code) = body.get("code").and_then(Value::as_i64)
        && code != 0
        && code != 200
    {
        let message = body
            .get("message")
            .or_else(|| body.get("msg"))
            .and_then(Value::as_str)
            .unwrap_or("unknown error");
        return invalid(format!("CodeBuddy rejected the token: {message}"), checked_at);
    }

    let uid = body.get("data").filter(|value| !value.is_null()).and_then(account_uid);
    match uid {
        Some(uid) if uid == expected_uid => VerifyResult {
            status: VerifyStatus::Valid,
            message: None,
            checked_at,
        },
        Some(uid) => invalid(format!("the token belongs to another account ({uid})"), checked_at),
        None => VerifyResult {
            status: VerifyStatus::Error,
            message: Some("CodeBuddy did not return an account profile".to_owned()),
            checked_at,
        },
    }
}

fn invalid(message: impl Into<String>, checked_at: i64) -> VerifyResult {
    VerifyResult {
        status: VerifyStatus::Invalid,
        message: Some(message.into()),
        checked_at,
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_profile_is_valid() {
        let body = serde_json::json!({ "code": 0, "data": { "uid": "uid-a", "nickname": "A" } });
        let result = classify_account_response(200, &body, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Valid);
        assert!(result.message.is_none());
    }

    #[test]
    fn profile_for_another_account_is_invalid() {
        let body = serde_json::json!({ "code": 0, "data": { "uid": "uid-b" } });
        let result = classify_account_response(200, &body, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Invalid);
        assert!(result.message.unwrap().contains("another account"));
    }

    #[test]
    fn rejected_token_is_invalid() {
        let result = classify_account_response(401, &serde_json::Value::Null, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Invalid);
    }

    #[test]
    fn server_failure_is_an_error_not_an_invalid_account() {
        let result = classify_account_response(503, &serde_json::Value::Null, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Error);
        assert!(result.message.unwrap().contains("503"));
    }

    #[test]
    fn business_error_code_is_invalid() {
        let body = serde_json::json!({ "code": 12151, "message": "profile is not ready" });
        let result = classify_account_response(200, &body, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Invalid);
        assert!(result.message.unwrap().contains("profile is not ready"));
    }

    #[test]
    fn missing_profile_is_an_error() {
        let body = serde_json::json!({ "code": 0 });
        let result = classify_account_response(200, &body, "uid-a", 1);
        assert_eq!(result.status, VerifyStatus::Error);
    }
}
