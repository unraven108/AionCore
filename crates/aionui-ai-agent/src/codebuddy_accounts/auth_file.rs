//! Read CodeBuddy's global auth files.
//!
//! CodeBuddy (CLI and extension share the same store) writes login state to
//! `<base>/Data/Public/auth/<md5(authId)>.info`. `base` is derived from the
//! user's home directory only — `CODEBUDDY_CONFIG_DIR` does **not** move it —
//! so this is the single source of truth for "who is currently logged in".
//!
//! Historic files (`Tencent-Cloud.coding-copilot.<timestamp>.info`) are left
//! behind when a login is replaced; they still hold a valid token for the
//! previous account and are what the "scan history" import reads.
//!
//! The auth directory is shared with other CodeBuddy-family products
//! (WorkBuddy), so every lookup filters on the CodeBuddy auth id.

use std::path::{Path, PathBuf};

const EXTENSION_DIR: &str = "CodeBuddyExtension";
/// Auth id of the CodeBuddy product (`product.json` → `authentication.id`).
/// The same directory also holds other products' credentials (WorkBuddy), so
/// every lookup is restricted to this prefix.
pub(crate) const AUTH_FILE_PREFIX: &str = "Tencent-Cloud.coding-copilot";

#[derive(Debug, Clone)]
pub struct AuthFileInfo {
    pub path: PathBuf,
    pub uid: String,
    pub nickname: String,
    pub access_token: String,
    /// Long-lived token CodeBuddy uses to renew `access_token` without a new
    /// browser login. Absent in older credential files.
    pub refresh_token: Option<String>,
    /// API host the account belongs to (e.g. `www.codebuddy.cn`). Regional
    /// builds use different hosts, so refreshes must go to the same one.
    pub domain: Option<String>,
    pub token_type: String,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
    pub last_refresh: Option<i64>,
    /// `true` for the timestamped backups left by previous logins.
    pub has_timestamp_suffix: bool,
}

/// Platform directory holding CodeBuddy's `auth/*.info` files.
pub fn auth_dir() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let base = match std::env::consts::OS {
        "windows" => home.join("AppData").join("Local").join(EXTENSION_DIR),
        "macos" => home.join("Library").join("Application Support").join(EXTENSION_DIR),
        _ => home.join(".local").join("share").join(EXTENSION_DIR),
    };
    Some(base.join("Data").join("Public").join("auth"))
}

/// The live login: the newest `*.info` in the auth directory.
///
/// The file name is the product auth id (`Tencent-Cloud.coding-copilot.info`),
/// not a hash, so there is no fixed name to match. CodeBuddy rewrites the live
/// file on login and on every token refresh, while timestamped backups
/// (`<authId>.<ISO timestamp>.info`) keep the mtime of the file they were
/// renamed from — picking the newest therefore lands on the live credential.
pub fn read_current() -> Option<AuthFileInfo> {
    read_current_in(&auth_dir()?)
}

fn read_current_in(dir: &Path) -> Option<AuthFileInfo> {
    let mut best: Option<(std::time::SystemTime, AuthFileInfo)> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let path = entry.path();
        if !is_codebuddy_auth_file(&path) {
            continue;
        }
        let Some(info) = parse_info(&path) else {
            continue;
        };
        let modified = entry
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .unwrap_or(std::time::UNIX_EPOCH);
        if best.as_ref().is_none_or(|(at, _)| modified >= *at) {
            best = Some((modified, info));
        }
    }
    best.map(|(_, info)| info)
}

/// Whether a credential is currently valid.
///
/// Uses the access-token expiry only: that is what the account list shows and
/// what the sign-in page reports. A credential whose access token already
/// expired is treated as expired even when an old refresh token is still
/// within its own window — importing it would only produce an "Expired" row.
pub fn is_usable(info: &AuthFileInfo, now: i64) -> bool {
    match info.expires_at {
        Some(expires_at) => expires_at > now,
        // No expiry data: treat as usable rather than hiding a mystery account.
        None => true,
    }
}

/// Delete expired timestamped backups. The live credential is never touched:
/// CodeBuddy still owns it, even when it has expired.
pub fn remove_expired_backups() -> usize {
    auth_dir().map(|dir| remove_expired_backups_in(&dir)).unwrap_or(0)
}

fn remove_expired_backups_in(dir: &Path) -> usize {
    let now = aionui_common::now_ms();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_codebuddy_auth_file(&path) || !has_timestamp_suffix(&path) {
            continue;
        }
        let Some(info) = parse_info(&path) else {
            continue;
        };
        if !is_usable(&info, now) && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Every usable account ever logged in on this machine, newest first, deduped
/// by uid. Expired backups are skipped; [`remove_expired_backups`] deletes them.
pub fn scan_history() -> Vec<AuthFileInfo> {
    let Some(dir) = auth_dir() else {
        return Vec::new();
    };
    let now = aionui_common::now_ms();
    let mut infos: Vec<(std::time::SystemTime, AuthFileInfo)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_codebuddy_auth_file(&path) {
            continue;
        }
        if let Some(info) = parse_info(&path) {
            if !is_usable(&info, now) {
                continue;
            }
            let modified = entry
                .metadata()
                .ok()
                .and_then(|meta| meta.modified().ok())
                .unwrap_or(std::time::UNIX_EPOCH);
            infos.push((modified, info));
        }
    }
    infos.sort_by_key(|entry| std::cmp::Reverse(entry.0));

    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for (_, info) in infos {
        if seen.insert(info.uid.clone()) {
            result.push(info);
        }
    }
    result
}

fn is_info_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("info")
}

/// Whether the file belongs to CodeBuddy, not to another product sharing the
/// auth directory.
fn is_codebuddy_auth_file(path: &Path) -> bool {
    is_info_file(path)
        && path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(AUTH_FILE_PREFIX))
}

/// Timestamped backups keep the old login around:
/// `<authId>.2026-08-20T02-14-12-135Z.info`.
fn has_timestamp_suffix(path: &Path) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}").expect("valid regex"));
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| re.is_match(name))
}

fn parse_info(path: &Path) -> Option<AuthFileInfo> {
    let raw = std::fs::read_to_string(path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let account = value.get("account")?;
    let auth = value.get("auth")?;

    let uid = account
        .get("uid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    let access_token = auth.get("accessToken").and_then(|v| v.as_str())?.trim().to_owned();
    if uid.is_empty() || access_token.is_empty() {
        return None;
    }
    let nickname = account
        .get("nickname")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(&uid)
        .to_owned();

    Some(AuthFileInfo {
        path: path.to_path_buf(),
        uid,
        nickname,
        access_token,
        refresh_token: non_empty(auth.get("refreshToken")),
        domain: non_empty(auth.get("domain")),
        token_type: auth
            .get("tokenType")
            .and_then(|v| v.as_str())
            .unwrap_or("Bearer")
            .to_owned(),
        expires_at: auth.get("expiresAt").and_then(serde_json::Value::as_i64),
        refresh_expires_at: auth.get("refreshExpiresAt").and_then(serde_json::Value::as_i64),
        last_refresh: auth.get("lastRefreshTime").and_then(serde_json::Value::as_i64),
        has_timestamp_suffix: has_timestamp_suffix(path),
    })
}

fn non_empty(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// Rewrite the OAuth fields of a live credential file, preserving the rest.
///
/// Used after the host refreshes the account CodeBuddy itself is logged into:
/// if the refresh endpoint rotated the tokens, CodeBuddy's copy must move with
/// it or its next own refresh would fail. Writes atomically (temp + rename) so
/// a concurrent CodeBuddy read never sees a half-written file.
pub fn write_live_tokens(
    path: &Path,
    access_token: &str,
    refresh_token: Option<&str>,
    expires_at: Option<i64>,
    refresh_expires_at: Option<i64>,
    last_refresh: i64,
) -> std::io::Result<()> {
    let raw = std::fs::read_to_string(path)?;
    let mut value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let auth = value
        .get_mut("auth")
        .and_then(|auth| auth.as_object_mut())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "auth object missing"))?;

    auth.insert("accessToken".into(), serde_json::Value::String(access_token.to_owned()));
    if let Some(refresh_token) = refresh_token {
        auth.insert(
            "refreshToken".into(),
            serde_json::Value::String(refresh_token.to_owned()),
        );
    }
    if let Some(expires_at) = expires_at {
        auth.insert("expiresAt".into(), serde_json::json!(expires_at));
        auth.insert(
            "expiresIn".into(),
            serde_json::json!((expires_at - last_refresh).max(0) / 1000),
        );
    }
    if let Some(refresh_expires_at) = refresh_expires_at {
        auth.insert("refreshExpiresAt".into(), serde_json::json!(refresh_expires_at));
        auth.insert(
            "refreshExpiresIn".into(),
            serde_json::json!((refresh_expires_at - last_refresh).max(0) / 1000),
        );
    }
    auth.insert("lastRefreshTime".into(), serde_json::json!(last_refresh));

    let serialized = serde_json::to_string_pretty(&value)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let tmp = path.with_extension("info.tmp");
    std::fs::write(&tmp, serialized)?;
    restrict_permissions(&tmp);
    std::fs::rename(&tmp, path)
}

fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_info(dir: &Path, name: &str, uid: &str, token: &str) -> PathBuf {
        let path = dir.join(name);
        let payload = serde_json::json!({
            "account": { "uid": uid, "nickname": format!("nick-{uid}"), "type": "personal" },
            "auth": {
                "accessToken": token,
                "refreshToken": format!("refresh-{token}"),
                "domain": "www.codebuddy.cn",
                "tokenType": "Bearer",
                "expiresAt": 1_800_000_000_000_i64,
                "refreshExpiresAt": 1_800_100_000_000_i64,
                "lastRefreshTime": 1_799_000_000_000_i64
            }
        });
        std::fs::write(&path, payload.to_string()).expect("write info");
        path
    }

    #[test]
    fn parses_account_and_auth_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Real-world live filename: the product auth id, not a hash.
        let path = write_info(dir.path(), "Tencent-Cloud.coding-copilot.info", "uid-1", "token-1");
        let info = parse_info(&path).expect("parse");
        assert_eq!(info.uid, "uid-1");
        assert_eq!(info.nickname, "nick-uid-1");
        assert_eq!(info.access_token, "token-1");
        assert_eq!(info.refresh_token.as_deref(), Some("refresh-token-1"));
        assert_eq!(info.domain.as_deref(), Some("www.codebuddy.cn"));
        assert_eq!(info.expires_at, Some(1_800_000_000_000));
        assert!(!info.has_timestamp_suffix);
    }

    #[test]
    fn timestamped_backups_are_flagged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_info(
            dir.path(),
            "Tencent-Cloud.coding-copilot.2026-08-20T02-14-12-135Z.info",
            "uid-2",
            "token-2",
        );
        let info = parse_info(&path).expect("parse");
        assert!(info.has_timestamp_suffix);
    }

    #[test]
    fn current_login_is_the_newest_info_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_info(
            dir.path(),
            "Tencent-Cloud.coding-copilot.2026-08-20T02-14-12-135Z.info",
            "uid-old",
            "token-old",
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
        write_info(
            dir.path(),
            "Tencent-Cloud.coding-copilot.info",
            "uid-live",
            "token-live",
        );

        let current = read_current_in(dir.path()).expect("current login");
        assert_eq!(current.uid, "uid-live");
        assert!(!current.has_timestamp_suffix);
    }

    #[test]
    fn rejects_payloads_without_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.info");
        std::fs::write(&path, r#"{"account":{"uid":"u"},"auth":{}}"#).unwrap();
        assert!(parse_info(&path).is_none());
    }

    #[test]
    fn ignores_other_products_in_the_same_auth_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_info(dir.path(), "Tencent-Cloud.coding-copilot.info", "uid-cb", "token-cb");
        std::thread::sleep(std::time::Duration::from_millis(20));
        // Newer, but belongs to another product and must not win.
        write_info(dir.path(), "workbuddy-desktop.info", "uid-work", "token-work");

        let current = read_current_in(dir.path()).expect("current login");
        assert_eq!(current.uid, "uid-cb");
    }

    #[test]
    fn usability_follows_the_access_token() {
        let now = 1_000_000;
        let info = AuthFileInfo {
            path: PathBuf::new(),
            uid: "uid".into(),
            nickname: "uid".into(),
            access_token: "token".into(),
            refresh_token: Some("refresh".into()),
            domain: None,
            token_type: "Bearer".into(),
            expires_at: Some(now + 1),
            refresh_expires_at: Some(now - 1),
            last_refresh: None,
            has_timestamp_suffix: false,
        };
        assert!(is_usable(&info, now), "valid access token wins");

        let expired = AuthFileInfo {
            expires_at: Some(now - 1),
            refresh_expires_at: Some(now + 999),
            ..info.clone()
        };
        assert!(!is_usable(&expired, now), "expired access token is expired");

        let unknown = AuthFileInfo {
            expires_at: None,
            ..info
        };
        assert!(is_usable(&unknown, now), "unknown expiry is kept");
    }

    #[test]
    fn removes_expired_backups_but_never_the_live_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let expired = write_expiring(
            dir.path(),
            "Tencent-Cloud.coding-copilot.2020-01-01T00-00-00-000Z.info",
            1_000,
        );
        let valid = write_expiring(
            dir.path(),
            "Tencent-Cloud.coding-copilot.2026-01-01T00-00-00-000Z.info",
            aionui_common::now_ms() + 86_400_000,
        );
        let live_expired = write_expiring(dir.path(), "Tencent-Cloud.coding-copilot.info", 1_000);

        assert_eq!(remove_expired_backups_in(dir.path()), 1);
        assert!(!expired.exists());
        assert!(valid.exists());
        assert!(live_expired.exists(), "the live credential is CodeBuddy's to manage");
    }

    fn write_expiring(dir: &Path, name: &str, expires_at: i64) -> PathBuf {
        let path = dir.join(name);
        let payload = serde_json::json!({
            "account": { "uid": "uid-1", "nickname": "nick" },
            "auth": {
                "accessToken": "token",
                "tokenType": "Bearer",
                "expiresAt": expires_at,
                "refreshExpiresAt": expires_at
            }
        });
        std::fs::write(&path, payload.to_string()).expect("write info");
        path
    }

    #[test]
    fn writes_refreshed_tokens_back_without_touching_the_account_block() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_info(dir.path(), "Tencent-Cloud.coding-copilot.info", "uid-1", "token-1");

        write_live_tokens(
            &path,
            "token-2",
            Some("refresh-token-2"),
            Some(2_000_000_000_000),
            Some(2_000_100_000_000),
            1_900_000_000_000,
        )
        .expect("write");

        let info = parse_info(&path).expect("parse");
        assert_eq!(info.uid, "uid-1");
        assert_eq!(info.access_token, "token-2");
        assert_eq!(info.refresh_token.as_deref(), Some("refresh-token-2"));
        assert_eq!(info.expires_at, Some(2_000_000_000_000));
        assert_eq!(info.refresh_expires_at, Some(2_000_100_000_000));
        assert_eq!(info.last_refresh, Some(1_900_000_000_000));

        let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["account"]["uid"], "uid-1");
        assert_eq!(value["auth"]["expiresIn"], 100_000_000_i64);
        assert!(!dir.path().join("Tencent-Cloud.coding-copilot.info.tmp").exists());
    }
}
