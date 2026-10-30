//! CodeBuddy multi-account support.
//!
//! CodeBuddy stores its login state in a single global file
//! (`<sharedDataPath>/auth/<md5(authId)>.info`), so accounts cannot be isolated
//! by directory. The CLI does honour `CODEBUDDY_AUTH_TOKEN` with the highest
//! storage priority (see `CustomTokenAuthenticationStorageImpl.priority()` in
//! `@tencent-ai/codebuddy-code`), which is what this module builds on:
//!
//! - a local account library (`<data_dir>/codebuddy-accounts.json`) holds one
//!   Bearer token + refresh token per account, plus a per-account
//!   `CODEBUDDY_CONFIG_DIR` for session/settings isolation;
//! - spawning a CodeBuddy agent injects the active account's token and config
//!   dir (see `factory::acp`), renewing the token first when it is near expiry;
//! - switching accounts is a local activation flag, effective for new sessions.
//!
//! Renewal details live in [`refresh`]. Tokens are stored in plain text on the
//! local machine; the HTTP layer never returns a full token.

pub(crate) mod auth_file;
mod import;
mod login;
mod refresh;
mod usage;
mod verify;

pub use auth_file::{AuthFileInfo, auth_dir, read_current, scan_history};
pub use import::{ImportSummary, import_cockpit_export};
pub use login::{LoginManager, LoginSessionView, LoginStart, LoginStatus};
pub use refresh::{
    RefreshSummary, adopt_live_for_current, backfill_from_history, ensure_fresh, needs_refresh, refresh_expiring,
};
pub use verify::{VerifyResult, VerifyStatus, verify_account};

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const ACCOUNTS_FILE: &str = "codebuddy-accounts.json";
pub(crate) const PROFILES_DIR: &str = "codebuddy-accounts";
const TOKEN_PREVIEW_HEAD: usize = 6;
const TOKEN_PREVIEW_TAIL: usize = 4;

/// One account in the local library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAccount {
    /// Stable id: the CodeBuddy `account.uid`.
    pub id: String,
    /// Display name reported by CodeBuddy (`account.nickname`).
    pub name: String,
    pub uid: String,
    /// Bearer access token, without the `Bearer ` prefix.
    pub access_token: String,
    /// Token used to renew `access_token` without a browser login. Stored so a
    /// library entry keeps working long after the access token expires.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// API host for this account (`www.codebuddy.cn`, `www.codebuddy.ai`, …).
    /// Refresh requests must go to the same regional host.
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub token_type: String,
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub refresh_expires_at: Option<i64>,
    #[serde(default)]
    pub last_refresh: Option<i64>,
    /// Directory injected as `CODEBUDDY_CONFIG_DIR` for this account.
    pub profile_dir: String,
    /// `login` | `import` | `history`
    #[serde(default)]
    pub source: String,
    /// When false, automatic failover never switches to this account. The user
    /// can still activate it manually.
    #[serde(default = "default_true")]
    pub auto_switch_enabled: bool,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub last_used_at: i64,
}

/// Wire shape for the account list. Never carries the full token.
#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    pub id: String,
    pub name: String,
    pub uid: String,
    pub token_preview: String,
    pub expires_at: Option<i64>,
    pub refresh_expires_at: Option<i64>,
    pub source: String,
    pub is_active: bool,
    pub is_expired: bool,
    /// Whether a refresh token is stored, i.e. automatic renewal can work.
    pub can_refresh: bool,
    /// Whether automatic failover may switch to this account.
    pub auto_switch_enabled: bool,
    /// Credits this account spent since local midnight. `0.0` when unknown.
    pub today_credits: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub active_id: Option<String>,
    #[serde(default)]
    pub accounts: Vec<StoredAccount>,
}

fn default_version() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

impl Default for AccountsFile {
    fn default() -> Self {
        Self {
            version: 1,
            active_id: None,
            accounts: Vec::new(),
        }
    }
}

/// File-backed account library. Cheap to clone; every operation reads or
/// writes the JSON file (the spawn path is not hot enough to warrant a cache,
/// and a cache would need invalidation across the router and factory copies).
#[derive(Debug, Clone)]
pub struct CodeBuddyAccountStore {
    root: PathBuf,
    path: PathBuf,
}

impl CodeBuddyAccountStore {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        let root = data_dir.as_ref().to_path_buf();
        let path = root.join(ACCOUNTS_FILE);
        Self { root, path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn read(&self) -> AccountsFile {
        match std::fs::read_to_string(&self.path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => AccountsFile::default(),
        }
    }

    fn write(&self, file: &AccountsFile) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(file).unwrap_or_else(|_| "{}".to_owned());
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, raw.as_bytes())?;
        restrict_permissions(&tmp);
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Accounts sorted by display name, plus the active id.
    pub fn list(&self) -> (Vec<StoredAccount>, Option<String>) {
        let file = self.read();
        (file.accounts, file.active_id)
    }

    /// The active account, if any. Read on every spawn.
    pub fn active(&self) -> Option<StoredAccount> {
        let file = self.read();
        let active_id = file.active_id?;
        file.accounts.into_iter().find(|account| account.id == active_id)
    }

    /// Insert or update by uid. Keeps the existing `created_at`.
    pub fn upsert(&self, mut account: StoredAccount) -> std::io::Result<()> {
        let mut file = self.read();
        if let Some(existing) = file.accounts.iter().find(|item| item.id == account.id) {
            account.created_at = existing.created_at;
        }
        file.accounts.retain(|item| item.id != account.id);
        file.accounts.push(account);
        if file.active_id.is_none() {
            file.active_id = file.accounts.first().map(|item| item.id.clone());
        }
        self.write(&file)
    }

    pub fn activate(&self, id: &str) -> std::io::Result<bool> {
        let mut file = self.read();
        if !file.accounts.iter().any(|item| item.id == id) {
            return Ok(false);
        }
        file.active_id = Some(id.to_owned());
        if let Some(account) = file.accounts.iter_mut().find(|item| item.id == id) {
            account.last_used_at = aionui_common::now_ms();
        }
        self.write(&file)?;
        Ok(true)
    }

    /// Allow or forbid automatic failover into an account. Manual activation is
    /// unaffected. Returns `Ok(false)` when the id is unknown.
    pub fn set_auto_switch_enabled(&self, id: &str, enabled: bool) -> std::io::Result<bool> {
        let mut file = self.read();
        let Some(account) = file.accounts.iter_mut().find(|item| item.id == id) else {
            return Ok(false);
        };
        if account.auto_switch_enabled == enabled {
            return Ok(true);
        }
        account.auto_switch_enabled = enabled;
        self.write(&file)?;
        Ok(true)
    }

    /// The account with this id, if it is still in the library.
    ///
    /// Read on spawn for a conversation that pinned its account
    /// (`extra.codebuddy_account_id`). `None` means the account was removed or
    /// never existed; callers fall back to [`Self::active`].
    pub fn get(&self, id: &str) -> Option<StoredAccount> {
        self.read().accounts.into_iter().find(|account| account.id == id)
    }

    /// Next account to use when the active one fails. Excludes the active
    /// account and accounts that can neither present a valid access token nor
    /// renew one; prefers the least recently used so retries spread across the
    /// library instead of hammering one account.
    pub fn next_usable_account(&self, now: i64) -> Option<StoredAccount> {
        let file = self.read();
        let active_id = file.active_id.as_deref();
        let mut candidates: Vec<StoredAccount> = file
            .accounts
            .into_iter()
            .filter(|account| Some(account.id.as_str()) != active_id)
            .filter(|account| usable_for_failover(account, now))
            .collect();
        candidates.sort_by(|left, right| {
            left.last_used_at
                .cmp(&right.last_used_at)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        candidates.into_iter().next()
    }

    /// Activate the account chosen by [`Self::next_usable_account`].
    ///
    /// Returns the newly active account, or `None` when there is no other
    /// usable account or the library cannot be written.
    pub fn activate_next_usable(&self) -> Option<StoredAccount> {
        let now = aionui_common::now_ms();
        let mut file = self.read();
        let active_id = file.active_id.clone();
        let next_id = {
            let mut candidates: Vec<&StoredAccount> = file
                .accounts
                .iter()
                .filter(|account| Some(&account.id) != active_id.as_ref())
                .filter(|account| usable_for_failover(account, now))
                .collect();
            candidates.sort_by(|left, right| {
                left.last_used_at
                    .cmp(&right.last_used_at)
                    .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            });
            candidates.first().map(|account| account.id.clone())?
        };

        file.active_id = Some(next_id.clone());
        let next = file.accounts.iter_mut().find(|account| account.id == next_id)?;
        next.last_used_at = now;
        let activated = next.clone();
        self.write(&file).ok()?;
        Some(activated)
    }

    pub fn remove(&self, id: &str) -> std::io::Result<bool> {
        let mut file = self.read();
        let before = file.accounts.len();
        file.accounts.retain(|item| item.id != id);
        if file.accounts.len() == before {
            return Ok(false);
        }
        if file.active_id.as_deref() == Some(id) {
            file.active_id = file.accounts.first().map(|item| item.id.clone());
        }
        self.write(&file)?;
        Ok(true)
    }

    /// `CODEBUDDY_CONFIG_DIR` for a given account id.
    pub fn profile_dir(&self, account_id: &str) -> PathBuf {
        self.root.join(PROFILES_DIR).join(account_id)
    }

    pub fn to_view(&self, account: &StoredAccount, active_id: Option<&str>) -> AccountView {
        AccountView {
            id: account.id.clone(),
            name: account.name.clone(),
            uid: account.uid.clone(),
            token_preview: preview_token(&account.access_token),
            expires_at: account.expires_at,
            refresh_expires_at: account.refresh_expires_at,
            source: account.source.clone(),
            is_active: active_id.is_some_and(|id| id == account.id),
            is_expired: account.expires_at.is_some_and(|at| at <= aionui_common::now_ms()),
            can_refresh: has_refresh_token(account),
            auto_switch_enabled: account.auto_switch_enabled,
            today_credits: 0.0,
        }
    }

    pub fn views(&self) -> (Vec<AccountView>, Option<String>) {
        let (mut accounts, active_id) = self.list();
        // The active account always leads the list (settings list and the
        // conversation switcher share this ordering), then most recently used.
        accounts.sort_by(|left, right| {
            let left_active = active_id.as_deref() == Some(left.id.as_str());
            let right_active = active_id.as_deref() == Some(right.id.as_str());
            right_active
                .cmp(&left_active)
                .then(right.last_used_at.cmp(&left.last_used_at))
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        let today_credits = usage::today_credits_by_account(&self.root);
        let views = accounts
            .iter()
            .map(|account| {
                let mut view = self.to_view(account, active_id.as_deref());
                view.today_credits = today_credits.get(&account.id).copied().unwrap_or(0.0);
                view
            })
            .collect();
        (views, active_id)
    }
}

fn preview_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() <= TOKEN_PREVIEW_HEAD + TOKEN_PREVIEW_TAIL + 1 {
        return "…".to_owned();
    }
    let head: String = chars[..TOKEN_PREVIEW_HEAD].iter().collect();
    let tail: String = chars[chars.len() - TOKEN_PREVIEW_TAIL..].iter().collect();
    format!("{head}…{tail}")
}

fn has_refresh_token(account: &StoredAccount) -> bool {
    account.refresh_token.as_deref().is_some_and(|token| !token.is_empty())
}

/// Whether an account can still be tried after another one failed.
///
/// A valid access token is always enough. An expired access token is still
/// usable when a refresh token exists and has not itself expired (an unknown
/// refresh-token expiry is treated as still usable). Accounts the user excluded
/// from automatic switching are never candidates.
fn usable_for_failover(account: &StoredAccount, now: i64) -> bool {
    if !account.auto_switch_enabled {
        return false;
    }
    if account.expires_at.is_none_or(|at| at > now) {
        return true;
    }
    has_refresh_token(account) && account.refresh_expires_at.is_none_or(|at| at > now)
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

/// Build a stored account from a parsed auth file.
pub fn stored_account_from(info: &AuthFileInfo, store: &CodeBuddyAccountStore, source: &str) -> StoredAccount {
    let now = aionui_common::now_ms();
    StoredAccount {
        id: info.uid.clone(),
        name: info.nickname.clone(),
        uid: info.uid.clone(),
        access_token: info.access_token.clone(),
        refresh_token: info.refresh_token.clone(),
        domain: info.domain.clone(),
        token_type: info.token_type.clone(),
        expires_at: info.expires_at,
        refresh_expires_at: info.refresh_expires_at,
        last_refresh: info.last_refresh,
        profile_dir: store.profile_dir(&info.uid).to_string_lossy().into_owned(),
        source: source.to_owned(),
        auto_switch_enabled: true,
        created_at: now,
        last_used_at: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, CodeBuddyAccountStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = CodeBuddyAccountStore::new(dir.path());
        (dir, store)
    }

    fn account(id: &str, token: &str) -> StoredAccount {
        StoredAccount {
            id: id.into(),
            name: format!("user-{id}"),
            uid: id.into(),
            access_token: token.into(),
            refresh_token: Some(format!("refresh-{token}")),
            domain: Some("www.codebuddy.ai".into()),
            token_type: "Bearer".into(),
            expires_at: Some(aionui_common::now_ms() + 86_400_000),
            refresh_expires_at: None,
            last_refresh: None,
            profile_dir: String::new(),
            source: "import".into(),
            auto_switch_enabled: true,
            created_at: 0,
            last_used_at: 0,
        }
    }

    #[test]
    fn upsert_activate_and_remove() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        store.upsert(account("uid-b", "token-bbbbbb-2222")).unwrap();

        let (accounts, active_id) = store.list();
        assert_eq!(accounts.len(), 2);
        assert_eq!(active_id.as_deref(), Some("uid-a"), "first account becomes active");

        assert!(store.activate("uid-b").unwrap());
        assert_eq!(store.active().map(|a| a.id), Some("uid-b".to_owned()));

        assert!(store.remove("uid-b").unwrap());
        assert_eq!(store.active().map(|a| a.id), Some("uid-a".to_owned()));
    }

    #[test]
    fn views_mask_tokens() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "abcdefghijklmnop")).unwrap();
        let (views, _) = store.views();
        assert_eq!(views[0].token_preview, "abcdef…mnop");
        assert!(!views[0].token_preview.contains("ghijkl"));
        assert!(views[0].is_active);
    }

    #[test]
    fn views_put_the_active_account_first() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-a-1111")).unwrap();
        store.upsert(account("uid-b", "token-b-2222")).unwrap();
        store.upsert(account("uid-c", "token-c-3333")).unwrap();

        store.activate("uid-c").unwrap();
        let (views, active_id) = store.views();
        assert_eq!(active_id.as_deref(), Some("uid-c"));
        assert_eq!(views[0].id, "uid-c");
        assert!(views[0].is_active);

        store.activate("uid-a").unwrap();
        let (views, _) = store.views();
        assert_eq!(views[0].id, "uid-a");
    }

    #[test]
    fn expired_accounts_are_flagged() {
        let (_dir, store) = temp_store();
        let mut expired = account("uid-old", "token-old-0000");
        expired.expires_at = Some(aionui_common::now_ms() - 1_000);
        store.upsert(expired).unwrap();
        let (views, _) = store.views();
        assert!(views[0].is_expired);
    }

    #[test]
    fn view_reports_whether_automatic_renewal_is_possible() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        let mut no_refresh = account("uid-b", "token-bbbbbb-2222");
        no_refresh.refresh_token = None;
        store.upsert(no_refresh).unwrap();

        let (views, _) = store.views();
        let with_refresh = views.iter().find(|view| view.id == "uid-a").unwrap();
        let without_refresh = views.iter().find(|view| view.id == "uid-b").unwrap();
        assert!(with_refresh.can_refresh);
        assert!(!without_refresh.can_refresh);
    }

    #[test]
    fn next_usable_account_skips_the_active_and_dead_accounts() {
        let (_dir, store) = temp_store();
        let now = aionui_common::now_ms();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        let mut expired_no_refresh = account("uid-b", "token-bbbbbb-2222");
        expired_no_refresh.expires_at = Some(now - 1_000);
        expired_no_refresh.refresh_token = None;
        store.upsert(expired_no_refresh).unwrap();
        let mut expired_but_renewable = account("uid-c", "token-cccccc-3333");
        expired_but_renewable.expires_at = Some(now - 1_000);
        expired_but_renewable.refresh_expires_at = Some(now + 86_400_000);
        store.upsert(expired_but_renewable).unwrap();

        store.activate("uid-a").unwrap();
        let next = store.next_usable_account(now).expect("renewable account");
        assert_eq!(next.id, "uid-c");
    }

    #[test]
    fn activate_next_usable_persists_the_switch() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        store.upsert(account("uid-b", "token-bbbbbb-2222")).unwrap();
        store.activate("uid-a").unwrap();

        let activated = store.activate_next_usable().expect("next account");
        assert_eq!(activated.id, "uid-b");
        assert_eq!(store.active().map(|account| account.id), Some("uid-b".to_owned()));
        assert!(activated.last_used_at > 0);
    }

    #[test]
    fn activate_next_usable_returns_none_without_an_alternative() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        assert!(store.activate_next_usable().is_none());
    }

    #[test]
    fn next_usable_account_skips_accounts_excluded_from_auto_switch() {
        let (_dir, store) = temp_store();
        let now = aionui_common::now_ms();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        store.upsert(account("uid-b", "token-bbbbbb-2222")).unwrap();
        store.upsert(account("uid-c", "token-cccccc-3333")).unwrap();
        store.activate("uid-a").unwrap();
        assert!(store.set_auto_switch_enabled("uid-b", false).unwrap());

        let next = store.next_usable_account(now).expect("next account");
        assert_eq!(next.id, "uid-c", "excluded account must be skipped");
    }

    #[test]
    fn activate_next_usable_returns_none_when_every_alternative_is_excluded() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();
        store.upsert(account("uid-b", "token-bbbbbb-2222")).unwrap();
        store.activate("uid-a").unwrap();
        assert!(store.set_auto_switch_enabled("uid-b", false).unwrap());

        assert!(store.activate_next_usable().is_none());
        assert_eq!(
            store.active().map(|account| account.id),
            Some("uid-a".to_owned()),
            "the active account must stay put when failover has no candidate"
        );
    }

    #[test]
    fn auto_switch_defaults_to_enabled_for_legacy_files() {
        let (dir, store) = temp_store();
        let raw = r#"{
            "version": 1,
            "active_id": "uid-a",
            "accounts": [{
                "id": "uid-a",
                "name": "Legacy",
                "uid": "uid-a",
                "access_token": "token-aaaaaa-1111",
                "profile_dir": ""
            }]
        }"#;
        std::fs::write(dir.path().join(ACCOUNTS_FILE), raw).unwrap();

        let (views, _) = store.views();
        assert!(views[0].auto_switch_enabled);
    }

    #[test]
    fn set_auto_switch_enabled_persists_and_reports_missing_ids() {
        let (_dir, store) = temp_store();
        store.upsert(account("uid-a", "token-aaaaaa-1111")).unwrap();

        assert!(store.set_auto_switch_enabled("uid-a", false).unwrap());
        let (views, _) = store.views();
        assert!(!views[0].auto_switch_enabled);
        assert!(
            !store
                .list()
                .0
                .into_iter()
                .find(|account| account.id == "uid-a")
                .unwrap()
                .auto_switch_enabled
        );

        assert!(!store.set_auto_switch_enabled("missing", false).unwrap());
    }
}
