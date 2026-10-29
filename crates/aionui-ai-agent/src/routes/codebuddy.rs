#![allow(clippy::disallowed_types)]

//! CodeBuddy multi-account routes.
//!
//! The account library lives next to the other agent endpoints because it only
//! affects how the CodeBuddy ACP process is spawned.
//!
//! - `GET    /api/codebuddy/accounts` — account library + active account
//! - `POST   /api/codebuddy/accounts/refresh` — renew tokens close to expiry
//! - `POST   /api/codebuddy/accounts/scan` — discover accounts in CodeBuddy's auth dir
//! - `POST   /api/codebuddy/accounts/import` — save a discovered account
//! - `POST   /api/codebuddy/accounts/import-file` — import a cockpit-tools JSON export
//! - `POST   /api/codebuddy/accounts/{id}/activate` — switch active account
//! - `POST   /api/codebuddy/accounts/{id}/verify` — check that a token still works
//! - `DELETE /api/codebuddy/accounts/{id}` — remove from the library
//! - `POST   /api/codebuddy/accounts/login` — start browser sign-in
//! - `GET    /api/codebuddy/accounts/login/{sid}` — poll the login session
//! - `POST   /api/codebuddy/accounts/login/{sid}/cancel` — stop waiting

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use aionui_api_types::ApiResponse;
use aionui_common::ApiError;

use crate::codebuddy_accounts::{
    AccountView, CodeBuddyAccountStore, ImportSummary, LoginManager, LoginSessionView, LoginStart, RefreshSummary,
    VerifyResult, adopt_live_for_current, auth_file, backfill_from_history, ensure_fresh, import_cockpit_export,
    refresh_expiring, stored_account_from, verify_account,
};

#[derive(Clone)]
pub struct CodeBuddyRouterState {
    pub store: Arc<CodeBuddyAccountStore>,
    pub login: Arc<LoginManager>,
}

pub fn codebuddy_account_routes(state: CodeBuddyRouterState) -> Router {
    Router::new()
        .route("/api/codebuddy/accounts", get(list_accounts))
        .route("/api/codebuddy/accounts/refresh", post(refresh_accounts))
        .route("/api/codebuddy/accounts/scan", post(scan_accounts))
        .route("/api/codebuddy/accounts/import", post(import_account))
        .route("/api/codebuddy/accounts/import-file", post(import_file))
        .route("/api/codebuddy/accounts/{id}/activate", post(activate_account))
        .route("/api/codebuddy/accounts/{id}/verify", post(verify_stored_account))
        .route("/api/codebuddy/accounts/{id}", delete(remove_account))
        .route("/api/codebuddy/accounts/login", post(start_login))
        .route("/api/codebuddy/accounts/login/{sid}", get(login_status))
        .route("/api/codebuddy/accounts/login/{sid}/cancel", post(cancel_login))
        .with_state(state)
}

#[derive(Debug, Serialize)]
pub struct CodeBuddyAccountsResponse {
    pub active_id: Option<String>,
    pub accounts: Vec<AccountView>,
    /// Where CodeBuddy keeps `auth/*.info`, when the directory exists.
    pub auth_dir: Option<String>,
    /// UID of the account CodeBuddy currently has on disk.
    pub current_uid: Option<String>,
}

async fn list_accounts(
    State(state): State<CodeBuddyRouterState>,
) -> Result<Json<ApiResponse<CodeBuddyAccountsResponse>>, ApiError> {
    // Keep the list honest when CodeBuddy refreshed the live login itself, and
    // upgrade library entries saved before refresh tokens were stored.
    backfill_from_history(&state.store);
    adopt_live_for_current(&state.store);
    let (accounts, active_id) = state.store.views();
    let current = auth_file::read_current();
    Ok(Json(ApiResponse::ok(CodeBuddyAccountsResponse {
        active_id,
        accounts,
        // Only report the directory when it exists: the settings card hides
        // itself entirely on machines where CodeBuddy was never used.
        auth_dir: auth_file::auth_dir()
            .filter(|path| path.exists())
            .map(|path| path.to_string_lossy().into_owned()),
        current_uid: current.map(|info| info.uid),
    })))
}

async fn refresh_accounts(
    State(state): State<CodeBuddyRouterState>,
) -> Result<Json<ApiResponse<RefreshSummary>>, ApiError> {
    let summary = refresh_expiring(&state.store).await;
    Ok(Json(ApiResponse::ok(summary)))
}

#[derive(Debug, Serialize)]
pub struct ScanItem {
    pub uid: String,
    pub name: String,
    pub expires_at: Option<i64>,
    /// `true` for timestamped backups left behind by previous logins.
    pub from_history: bool,
    pub already_imported: bool,
}

#[derive(Debug, Serialize)]
pub struct ScanResponse {
    pub items: Vec<ScanItem>,
    /// Expired timestamped backups removed while scanning.
    pub removed_expired: usize,
}

async fn scan_accounts(State(state): State<CodeBuddyRouterState>) -> Result<Json<ApiResponse<ScanResponse>>, ApiError> {
    // Expired backups are useless for "add an account"; clean them up so the
    // list only offers credentials that can still sign in.
    let removed_expired = auth_file::remove_expired_backups();
    let (accounts, _) = state.store.list();
    let imported: std::collections::HashSet<String> = accounts.iter().map(|account| account.id.clone()).collect();
    let mut items: Vec<ScanItem> = auth_file::scan_history()
        .into_iter()
        .map(|info| ScanItem {
            already_imported: imported.contains(&info.uid),
            uid: info.uid,
            name: info.nickname,
            expires_at: info.expires_at,
            from_history: info.has_timestamp_suffix,
        })
        .collect();

    // Accounts that only exist in the library — imported from a cockpit-tools
    // export, or whose on-disk backup has already been cleaned up — still
    // belong in the overview. Expired library entries stay hidden, matching the
    // "only usable accounts" rule above.
    let now = aionui_common::now_ms();
    for account in accounts {
        if items.iter().any(|item| item.uid == account.uid) {
            continue;
        }
        if account.expires_at.is_some_and(|expires_at| expires_at <= now) {
            continue;
        }
        items.push(ScanItem {
            uid: account.uid,
            name: account.name,
            expires_at: account.expires_at,
            from_history: false,
            already_imported: true,
        });
    }

    Ok(Json(ApiResponse::ok(ScanResponse { items, removed_expired })))
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    /// Account uid from `/scan`; omitted with `current: true`.
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub current: bool,
}

async fn import_account(
    State(state): State<CodeBuddyRouterState>,
    Json(request): Json<ImportRequest>,
) -> Result<Json<ApiResponse<AccountView>>, ApiError> {
    let target = if request.current {
        auth_file::read_current().filter(|info| auth_file::is_usable(info, aionui_common::now_ms()))
    } else {
        let uid = request
            .uid
            .as_deref()
            .ok_or_else(|| ApiError::BadRequest("uid or current=true is required".into()))?;
        auth_file::scan_history().into_iter().find(|info| info.uid == uid)
    }
    .ok_or_else(|| ApiError::NotFound("no usable CodeBuddy account on disk".into()))?;

    let source = if target.has_timestamp_suffix {
        "history"
    } else {
        "import"
    };
    let account = stored_account_from(&target, &state.store, source);
    state.store.upsert(account.clone()).map_err(io_error)?;
    let (_, active_id) = state.store.list();
    let view = state.store.to_view(&account, active_id.as_deref());
    Ok(Json(ApiResponse::ok(view)))
}

const MAX_IMPORT_BYTES: u64 = 20 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct ImportFileRequest {
    /// Absolute path chosen through the desktop file dialog.
    pub path: String,
}

async fn import_file(
    State(state): State<CodeBuddyRouterState>,
    Json(request): Json<ImportFileRequest>,
) -> Result<Json<ApiResponse<ImportSummary>>, ApiError> {
    let path = request.path.trim();
    if path.is_empty() {
        return Err(ApiError::BadRequest("path is required".into()));
    }
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|error| ApiError::BadRequest(format!("cannot read '{path}': {error}")))?;
    if metadata.len() > MAX_IMPORT_BYTES {
        return Err(ApiError::BadRequest("import file is larger than 20 MB".into()));
    }
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|error| ApiError::BadRequest(format!("cannot read '{path}': {error}")))?;
    let summary = import_cockpit_export(&state.store, &raw).map_err(ApiError::BadRequest)?;
    Ok(Json(ApiResponse::ok(summary)))
}

async fn activate_account(
    State(state): State<CodeBuddyRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<CodeBuddyAccountsResponse>>, ApiError> {
    // Switching is the user's chance to notice a stale account: renew now so
    // the next session starts with a fresh token instead of failing mid-turn.
    let account = state
        .store
        .list()
        .0
        .into_iter()
        .find(|account| account.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("account '{id}' not found")))?;
    ensure_fresh(&state.store, account).await;

    if !state.store.activate(&id).map_err(io_error)? {
        return Err(ApiError::NotFound(format!("account '{id}' not found")));
    }
    list_accounts(State(state)).await
}

async fn verify_stored_account(
    State(state): State<CodeBuddyRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<VerifyResult>>, ApiError> {
    let result = verify_account(&state.store, &id).await.map_err(ApiError::NotFound)?;
    Ok(Json(ApiResponse::ok(result)))
}

async fn remove_account(
    State(state): State<CodeBuddyRouterState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<CodeBuddyAccountsResponse>>, ApiError> {
    if !state.store.remove(&id).map_err(io_error)? {
        return Err(ApiError::NotFound(format!("account '{id}' not found")));
    }
    list_accounts(State(state)).await
}

async fn start_login(State(state): State<CodeBuddyRouterState>) -> Result<Json<ApiResponse<LoginStart>>, ApiError> {
    let start = state
        .login
        .start(&state.store)
        .await
        .map_err(|error| ApiError::Internal(format!("codebuddy sign-in: {error}")))?;
    Ok(Json(ApiResponse::ok(start)))
}

async fn cancel_login(
    State(state): State<CodeBuddyRouterState>,
    Path(sid): Path<String>,
) -> Result<Json<ApiResponse<LoginSessionView>>, ApiError> {
    if !state.login.cancel(&sid) {
        return Err(ApiError::NotFound(format!("login session '{sid}' not found")));
    }
    state
        .login
        .status(&sid)
        .map(|view| Json(ApiResponse::ok(view)))
        .ok_or_else(|| ApiError::NotFound(format!("login session '{sid}' not found")))
}

async fn login_status(
    State(state): State<CodeBuddyRouterState>,
    Path(sid): Path<String>,
) -> Result<Json<ApiResponse<LoginSessionView>>, ApiError> {
    state
        .login
        .status(&sid)
        .map(|view| Json(ApiResponse::ok(view)))
        .ok_or_else(|| ApiError::NotFound(format!("login session '{sid}' not found")))
}

fn io_error(error: std::io::Error) -> ApiError {
    ApiError::Internal(format!("codebuddy accounts: {error}"))
}
