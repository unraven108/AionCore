//! Import accounts exported by cockpit-tools.
//!
//! The export is a JSON array (or `{ "accounts": [...] }`) of account objects
//! with `uid`, `email`, `nickname`, `access_token`, `refresh_token`,
//! `expires_at`, `domain` and the raw CodeBuddy payloads under `auth_raw`.
//! `auth_raw` is used as a fallback so exports that only carry the raw blob
//! still import with their refresh token.

use serde::Serialize;
use serde_json::Value;

use super::{CodeBuddyAccountStore, StoredAccount};

#[derive(Debug, Default, Clone, Serialize)]
pub struct ImportSummary {
    pub imported: usize,
    pub skipped: usize,
}

/// Parse an export and upsert every usable account (matched by `uid`).
pub fn import_cockpit_export(store: &CodeBuddyAccountStore, raw: &str) -> Result<ImportSummary, String> {
    let value: Value = serde_json::from_str(raw).map_err(|error| format!("invalid JSON: {error}"))?;
    let items = collect_items(&value)?;
    if items.is_empty() {
        return Err("the file contains no accounts".to_owned());
    }

    let mut summary = ImportSummary::default();
    let mut parsed = 0;
    for item in items {
        match account_from_export(item, store) {
            Some(account) => {
                parsed += 1;
                // Never downgrade an account whose local token is newer: the
                // export is a snapshot and may predate a host-side refresh.
                let newer_locally = store
                    .list()
                    .0
                    .into_iter()
                    .find(|existing| existing.id == account.id)
                    .is_some_and(|existing| existing.expires_at.unwrap_or(0) > account.expires_at.unwrap_or(0));
                if newer_locally {
                    summary.skipped += 1;
                    continue;
                }
                match store.upsert(account) {
                    Ok(()) => summary.imported += 1,
                    Err(error) => {
                        tracing::warn!(%error, "failed to store an imported CodeBuddy account");
                        summary.skipped += 1;
                    }
                }
            }
            None => summary.skipped += 1,
        }
    }

    if parsed == 0 {
        return Err(format!(
            "no usable accounts in the file ({} entr{} skipped)",
            summary.skipped,
            if summary.skipped == 1 { "y" } else { "ies" }
        ));
    }
    Ok(summary)
}

fn collect_items(value: &Value) -> Result<Vec<&Value>, String> {
    match value {
        Value::Array(items) => Ok(items.iter().collect()),
        Value::Object(map) => {
            for key in ["accounts", "items", "data"] {
                if let Some(Value::Array(items)) = map.get(key) {
                    return Ok(items.iter().collect());
                }
            }
            // A single account object.
            Ok(vec![value])
        }
        _ => Err("expected a JSON array or object".to_owned()),
    }
}

fn account_from_export(item: &Value, store: &CodeBuddyAccountStore) -> Option<StoredAccount> {
    let auth = item.get("auth_raw").filter(|value| value.is_object());
    let uid = text(item, &["uid", "user_id", "userId"])?;
    let access_token = text(item, &["access_token", "accessToken", "token"])
        .or_else(|| auth.and_then(|auth| text(auth, &["accessToken"])))?;

    let now = aionui_common::now_ms();
    let name = text(item, &["nickname", "name", "email"]).unwrap_or_else(|| uid.clone());
    let refresh_token =
        text(item, &["refresh_token", "refreshToken"]).or_else(|| auth.and_then(|auth| text(auth, &["refreshToken"])));
    let expires_at =
        timestamp(item, &["expires_at", "expiresAt"]).or_else(|| auth.and_then(|auth| timestamp(auth, &["expiresAt"])));
    let refresh_expires_at = timestamp(item, &["refresh_expires_at", "refreshExpiresAt"])
        .or_else(|| auth.and_then(|auth| timestamp(auth, &["refreshExpiresAt"])));
    let domain = text(item, &["domain"]).or_else(|| auth.and_then(|auth| text(auth, &["domain"])));
    let token_type = text(item, &["token_type", "tokenType"])
        .or_else(|| auth.and_then(|auth| text(auth, &["tokenType"])))
        .unwrap_or_else(|| "Bearer".to_owned());

    Some(StoredAccount {
        id: uid.clone(),
        name,
        uid: uid.clone(),
        access_token,
        refresh_token,
        domain,
        token_type,
        expires_at,
        refresh_expires_at,
        last_refresh: None,
        profile_dir: store.profile_dir(&uid).to_string_lossy().into_owned(),
        source: "cockpit".to_owned(),
        auto_switch_enabled: true,
        created_at: now,
        last_used_at: 0,
    })
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(text) = value.get(*key).and_then(Value::as_str) {
            let text = text.trim();
            if !text.is_empty() {
                return Some(text.to_owned());
            }
        }
    }
    None
}

fn timestamp(value: &Value, keys: &[&str]) -> Option<i64> {
    let raw = keys.iter().find_map(|key| value.get(*key).and_then(parse_i64))?;
    // Exports use milliseconds; accept seconds from older builds too.
    Some(if raw < 100_000_000_000 { raw * 1000 } else { raw })
}

fn parse_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str().and_then(|text| text.trim().parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, CodeBuddyAccountStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CodeBuddyAccountStore::new(dir.path());
        (dir, store)
    }

    #[test]
    fn imports_an_array_and_skips_entries_without_a_token() {
        let (_dir, store) = store();
        let raw = serde_json::json!([
            {
                "id": "codebuddy_abc",
                "email": "a@example.com",
                "uid": "uid-a",
                "nickname": "Unraven",
                "access_token": "access-a",
                "refresh_token": "refresh-a",
                "token_type": "Bearer",
                "expires_at": 1_800_000_000_000_i64,
                "domain": "www.codebuddy.cn"
            },
            { "uid": "uid-b", "email": "b@example.com", "access_token": "access-b" },
            { "uid": "uid-c", "email": "c@example.com" }
        ])
        .to_string();

        let summary = import_cockpit_export(&store, &raw).expect("import");
        assert_eq!(summary.imported, 2);
        assert_eq!(summary.skipped, 1);

        let (accounts, _) = store.list();
        assert_eq!(accounts.len(), 2);
        let a = accounts.iter().find(|account| account.uid == "uid-a").expect("a");
        assert_eq!(a.name, "Unraven");
        assert_eq!(a.refresh_token.as_deref(), Some("refresh-a"));
        assert_eq!(a.domain.as_deref(), Some("www.codebuddy.cn"));
        assert_eq!(a.source, "cockpit");
    }

    #[test]
    fn falls_back_to_the_raw_auth_blob_and_the_email() {
        let (_dir, store) = store();
        let raw = serde_json::json!({
            "accounts": [{
                "uid": "uid-a",
                "email": "a@example.com",
                "access_token": "access-a",
                "auth_raw": {
                    "refreshToken": "refresh-raw",
                    "refreshExpiresAt": "1800100000000",
                    "domain": "www.codebuddy.ai"
                }
            }]
        })
        .to_string();

        import_cockpit_export(&store, &raw).expect("import");
        let (accounts, _) = store.list();
        let a = &accounts[0];
        assert_eq!(a.name, "a@example.com");
        assert_eq!(a.refresh_token.as_deref(), Some("refresh-raw"));
        assert_eq!(a.refresh_expires_at, Some(1_800_100_000_000));
        assert_eq!(a.domain.as_deref(), Some("www.codebuddy.ai"));
    }

    #[test]
    fn rejects_files_without_usable_accounts() {
        let (_dir, store) = store();
        let raw = serde_json::json!([{ "uid": "uid-a" }]).to_string();
        assert!(import_cockpit_export(&store, &raw).is_err());
        assert!(import_cockpit_export(&store, "not json").is_err());
    }

    #[test]
    fn never_downgrades_a_newer_local_token() {
        let (_dir, store) = store();
        let newer = serde_json::json!([{
            "uid": "uid-a",
            "access_token": "access-new",
            "expires_at": 1_900_000_000_000_i64
        }])
        .to_string();
        import_cockpit_export(&store, &newer).expect("first import");

        let older = serde_json::json!([{
            "uid": "uid-a",
            "access_token": "access-old",
            "expires_at": 1_800_000_000_000_i64
        }])
        .to_string();
        let summary = import_cockpit_export(&store, &older).expect("second import");
        assert_eq!(summary.imported, 0);
        assert_eq!(summary.skipped, 1);

        let (accounts, _) = store.list();
        assert_eq!(accounts[0].access_token, "access-new");
    }
}
