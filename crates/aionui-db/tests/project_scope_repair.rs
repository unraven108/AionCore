//! File-backed startup wiring for the project-scope repair.
//!
//! The unit tests exercise `repair` directly; this test proves the repair is
//! actually invoked by `init_database` after a restart.

use std::sync::Arc;

use aionui_db::{Database, IProjectStore, ProjectKind, SqliteProjectStore, init_database};

fn store(db: &Database) -> Arc<dyn IProjectStore> {
    Arc::new(SqliteProjectStore::new(db.pool().clone()))
}

async fn add_user(pool: &aionui_db::SqlitePool, id: &str) {
    sqlx::query(
        "INSERT INTO users (id, user_type, username, password_hash, status, session_generation, created_at, updated_at) \
         VALUES (?, 'local', ?, '', 'active', 0, 1, 1)",
    )
    .bind(id)
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn startup_repairs_owner_drift_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aionui-backend.db");

    let db = init_database(&path).await.unwrap();
    let pool = db.pool().clone();
    let projects = store(&db);
    add_user(&pool, "user_drift").await;
    let folder = projects.upsert_folder("file:///ws", "file:///ws").await.unwrap();
    let (_project, entry) = projects
        .create_project_with_workspace_entry("system_default_user", &folder.folder_id, "ws", ProjectKind::Standard)
        .await
        .unwrap();
    sqlx::query("UPDATE project_explorer SET owner_user_id = 'user_drift' WHERE pe_id = ?")
        .bind(&entry.pe_id)
        .execute(&pool)
        .await
        .unwrap();
    db.close().await;

    let reopened = init_database(&path).await.unwrap();
    let owner: String = sqlx::query_scalar("SELECT owner_user_id FROM project_explorer WHERE pe_id = ?")
        .bind(&entry.pe_id)
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(
        owner, "system_default_user",
        "startup must re-align a drifted explorer owner with its project"
    );
    reopened.close().await;
}

#[tokio::test]
async fn startup_repair_is_a_noop_on_a_clean_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("aionui-backend.db");

    let db = init_database(&path).await.unwrap();
    db.close().await;

    let reopened = init_database(&path).await.unwrap();
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM project_explorer")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(entries, 0);
    reopened.close().await;
}
