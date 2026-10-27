//! Idempotent startup repair for the project-bind owner chain.
//!
//! The user-scope migration (030) asserts that `project_explorer.owner_user_id`
//! matches `projects.user_id`, but nothing enforces that invariant at runtime.
//! A user-identity change (account adoption, an older build writing with a
//! different owner, a restored backup) can leave explorer entries owned by a
//! user that no longer exists: the file panel then filters them out, and
//! attaching one of those folders hits the global `(project_id, folder_id)`
//! unique index and surfaces as a 500.
//!
//! This module re-aligns the owner chain and merges the duplicate projects
//! that such drift produces. It is intentionally a startup repair rather than
//! a migration: drift can reappear at any time, and a failing migration would
//! block startup entirely. On a healthy database it costs four COUNT queries
//! and returns without writing.

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};
use tracing::{debug, info, warn};

use crate::error::DbError;

const ORPHAN_ENTRIES_SQL: &str = "\
    SELECT COUNT(*) FROM project_explorer pe \
    WHERE NOT EXISTS (SELECT 1 FROM projects p WHERE p.project_id = pe.project_id)";

const OWNER_MISMATCH_SQL: &str = "\
    SELECT COUNT(*) FROM project_explorer pe \
    JOIN projects p ON p.project_id = pe.project_id \
    WHERE pe.owner_user_id <> p.user_id";

const DUPLICATE_WORKSPACE_GROUPS_SQL: &str = "\
    SELECT COUNT(*) FROM ( \
        SELECT 1 FROM project_explorer pe \
        JOIN projects p ON p.project_id = pe.project_id \
        WHERE pe.role = 'workspace' \
        GROUP BY p.user_id, pe.folder_id \
        HAVING COUNT(DISTINCT pe.project_id) > 1 \
    )";

const PROJECTS_WITHOUT_WORKSPACE_SQL: &str = "\
    SELECT COUNT(*) FROM projects p \
    WHERE NOT EXISTS ( \
        SELECT 1 FROM project_explorer pe \
        WHERE pe.project_id = p.project_id AND pe.role = 'workspace' \
    )";

/// Read-only drift summary. `is_clean` deliberately ignores
/// `projects_without_workspace`: that state cannot be repaired without
/// inventing a folder identity, so it is reported but never blocks the
/// repair path.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProjectScopeDrift {
    pub orphan_entries: i64,
    pub owner_mismatch: i64,
    pub duplicate_workspace_groups: i64,
    pub projects_without_workspace: i64,
}

impl ProjectScopeDrift {
    fn is_clean(self) -> bool {
        self.orphan_entries == 0 && self.owner_mismatch == 0 && self.duplicate_workspace_groups == 0
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ProjectScopeRepairReport {
    pub orphan_entries_deleted: u64,
    pub duplicate_groups_merged: u64,
    pub projects_deleted: u64,
    pub entries_reowned: u64,
    pub conversations_repointed: u64,
    pub teams_repointed: u64,
    pub attached_entries_moved: u64,
    pub attached_entries_dropped: u64,
    pub foreign_children_left: u64,
    pub residual_owner_mismatch: i64,
    pub projects_without_workspace: i64,
}

#[derive(Debug)]
struct WorkspaceProject {
    project_id: String,
    owner_user_id: String,
    folder_id: String,
    /// Latest conversation or team activity for the project; 0 when unused.
    activity_at: i64,
    project_updated_at: i64,
    project_created_at: i64,
    healthy_entries: i64,
}

/// Run the repair only when drift is present. Never returns an error: the
/// project explorer is not on the critical startup path, so a failed repair
/// must leave the database untouched and let the app start.
pub(crate) async fn repair_if_drifted(pool: &SqlitePool) {
    match detect(pool).await {
        Ok(drift) if drift.is_clean() => {
            if drift.projects_without_workspace > 0 {
                warn!(
                    code = "PROJECT_SCOPE_WORKSPACE_MISSING",
                    projects_without_workspace = drift.projects_without_workspace,
                    "projects without a workspace root cannot be repaired automatically"
                );
            }
            debug!("project scope is healthy");
            return;
        }
        Ok(drift) => {
            warn!(
                code = "PROJECT_SCOPE_DRIFT_DETECTED",
                orphan_entries = drift.orphan_entries,
                owner_mismatch = drift.owner_mismatch,
                duplicate_workspace_groups = drift.duplicate_workspace_groups,
                projects_without_workspace = drift.projects_without_workspace,
                "project explorer owner drift detected; repairing"
            );
        }
        Err(error) => {
            warn!(
                code = "PROJECT_SCOPE_REPAIR_FAILED",
                stage = "detect",
                error = %error,
                "project scope detection failed; continuing"
            );
            return;
        }
    }

    match repair(pool).await {
        Ok(report) => {
            info!(
                code = "PROJECT_SCOPE_REPAIRED",
                orphan_entries_deleted = report.orphan_entries_deleted,
                duplicate_groups_merged = report.duplicate_groups_merged,
                projects_deleted = report.projects_deleted,
                entries_reowned = report.entries_reowned,
                conversations_repointed = report.conversations_repointed,
                teams_repointed = report.teams_repointed,
                attached_entries_moved = report.attached_entries_moved,
                attached_entries_dropped = report.attached_entries_dropped,
                foreign_children_left = report.foreign_children_left,
                "project explorer owner drift repaired"
            );
            if report.residual_owner_mismatch > 0 || report.projects_without_workspace > 0 {
                warn!(
                    code = "PROJECT_SCOPE_RESIDUAL",
                    residual_owner_mismatch = report.residual_owner_mismatch,
                    projects_without_workspace = report.projects_without_workspace,
                    "project explorer remains partially inconsistent after repair"
                );
            }
        }
        Err(error) => {
            warn!(
                code = "PROJECT_SCOPE_REPAIR_FAILED",
                stage = "repair",
                error = %error,
                "project scope repair rolled back; continuing"
            );
        }
    }
}

async fn detect(pool: &SqlitePool) -> Result<ProjectScopeDrift, DbError> {
    let mut connection = pool.acquire().await?;
    Ok(ProjectScopeDrift {
        orphan_entries: count(&mut *connection, ORPHAN_ENTRIES_SQL).await?,
        owner_mismatch: count(&mut *connection, OWNER_MISMATCH_SQL).await?,
        duplicate_workspace_groups: count(&mut *connection, DUPLICATE_WORKSPACE_GROUPS_SQL).await?,
        projects_without_workspace: count(&mut *connection, PROJECTS_WITHOUT_WORKSPACE_SQL).await?,
    })
}

async fn count(
    connection: &mut sqlx::SqliteConnection,
    sql: &str,
) -> Result<i64, DbError> {
    let value = sqlx::query_scalar::<_, i64>(sql).fetch_one(&mut *connection).await?;
    Ok(value)
}

async fn repair(pool: &SqlitePool) -> Result<ProjectScopeRepairReport, DbError> {
    // `BEGIN IMMEDIATE` takes the writer lock up front, matching the existing
    // repository transaction pattern: the repair reads grouping state and then
    // writes it, so a deferred lock upgrade could otherwise hit SQLITE_BUSY.
    let mut connection = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *connection).await?;

    let result: Result<ProjectScopeRepairReport, DbError> = async {
        let orphan_entries_deleted = sqlx::query(
            "DELETE FROM project_explorer \
             WHERE NOT EXISTS (SELECT 1 FROM projects p WHERE p.project_id = project_explorer.project_id)",
        )
        .execute(&mut *connection)
        .await?
        .rows_affected();
        let mut report = ProjectScopeRepairReport {
            orphan_entries_deleted,
            ..Default::default()
        };

        merge_duplicate_projects(&mut *connection, &mut report).await?;

        report.entries_reowned = sqlx::query(
            "UPDATE project_explorer \
             SET owner_user_id = (SELECT p.user_id FROM projects p WHERE p.project_id = project_explorer.project_id) \
             WHERE owner_user_id <> (SELECT p.user_id FROM projects p WHERE p.project_id = project_explorer.project_id) \
               AND EXISTS ( \
                   SELECT 1 FROM projects p JOIN users u ON u.id = p.user_id \
                   WHERE p.project_id = project_explorer.project_id \
               )",
        )
        .execute(&mut *connection)
        .await?
        .rows_affected();

        report.residual_owner_mismatch = count(&mut *connection, OWNER_MISMATCH_SQL).await?;
        report.projects_without_workspace = count(&mut *connection, PROJECTS_WITHOUT_WORKSPACE_SQL).await?;

        Ok(report)
    }
    .await;

    match result {
        Ok(report) => match sqlx::query("COMMIT").execute(&mut *connection).await {
            Ok(_) => Ok(report),
            Err(error) => {
                let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
                Err(DbError::from(error))
            }
        },
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *connection).await;
            Err(error)
        }
    }
}

/// Merge projects that share `(projects.user_id, workspace folder)`.
///
/// The application itself prevents this state: `resolve_core` reuses the
/// project whose workspace already owns the folder. A second project therefore
/// only appears when the original binding was invisible because of owner drift.
/// The survivor is the most recently active project so the conversation the
/// user is looking at keeps its project identity.
async fn merge_duplicate_projects(
    connection: &mut sqlx::SqliteConnection,
    report: &mut ProjectScopeRepairReport,
) -> Result<(), DbError> {
    let rows = sqlx::query(
        "SELECT pe.project_id, p.user_id AS owner_user_id, pe.folder_id, \
                COALESCE((SELECT MAX(c.updated_at) FROM conversations c WHERE c.project_id = p.project_id), 0) \
                    AS conversation_at, \
                COALESCE((SELECT MAX(t.updated_at) FROM teams t WHERE t.project_id = p.project_id), 0) \
                    AS team_at, \
                p.updated_at AS project_updated_at, \
                p.created_at AS project_created_at, \
                (SELECT COUNT(*) FROM project_explorer x \
                 WHERE x.project_id = p.project_id AND x.owner_user_id = p.user_id) AS healthy_entries \
         FROM project_explorer pe \
         JOIN projects p ON p.project_id = pe.project_id \
         WHERE pe.role = 'workspace'",
    )
    .fetch_all(&mut *connection)
    .await?;

    let mut groups: HashMap<(String, String), Vec<WorkspaceProject>> = HashMap::new();
    for row in rows {
        let conversation_at: i64 = row.get("conversation_at");
        let team_at: i64 = row.get("team_at");
        let project = WorkspaceProject {
            project_id: row.get("project_id"),
            owner_user_id: row.get("owner_user_id"),
            folder_id: row.get("folder_id"),
            activity_at: conversation_at.max(team_at),
            project_updated_at: row.get("project_updated_at"),
            project_created_at: row.get("project_created_at"),
            healthy_entries: row.get("healthy_entries"),
        };
        groups
            .entry((project.owner_user_id.clone(), project.folder_id.clone()))
            .or_default()
            .push(project);
    }

    for group in groups.values_mut() {
        if group.len() < 2 {
            continue;
        }

        group.sort_by(|left, right| {
            right
                .activity_at
                .cmp(&left.activity_at)
                .then_with(|| right.project_updated_at.cmp(&left.project_updated_at))
                .then_with(|| right.project_created_at.cmp(&left.project_created_at))
                .then_with(|| {
                    (right.healthy_entries > 0).cmp(&(left.healthy_entries > 0))
                })
                .then_with(|| right.project_id.cmp(&left.project_id))
        });

        let survivor = &group[0];
        report.duplicate_groups_merged += 1;
        for loser in &group[1..] {
            // Attached rows that already exist on the survivor must go first:
            // moving them would violate the global `(project_id, folder_id)`
            // unique index.
            report.attached_entries_dropped += sqlx::query(
                "DELETE FROM project_explorer \
                 WHERE project_id = ? AND role <> 'workspace' \
                   AND EXISTS ( \
                       SELECT 1 FROM project_explorer s \
                       WHERE s.project_id = ? AND s.folder_id = project_explorer.folder_id \
                   )",
            )
            .bind(&loser.project_id)
            .bind(&survivor.project_id)
            .execute(&mut *connection)
            .await?
            .rows_affected();

            report.attached_entries_moved += sqlx::query(
                "UPDATE project_explorer SET project_id = ? WHERE project_id = ? AND role <> 'workspace'",
            )
            .bind(&survivor.project_id)
            .bind(&loser.project_id)
            .execute(&mut *connection)
            .await?
            .rows_affected();

            // Only move children that already belong to the loser's owner;
            // a foreign-owned child is a separate invariant violation and
            // moving it would transfer another user's data.
            report.conversations_repointed += sqlx::query(
                "UPDATE conversations SET project_id = ? WHERE project_id = ? AND user_id = ?",
            )
            .bind(&survivor.project_id)
            .bind(&loser.project_id)
            .bind(&loser.owner_user_id)
            .execute(&mut *connection)
            .await?
            .rows_affected();

            report.teams_repointed += sqlx::query(
                "UPDATE teams SET project_id = ? WHERE project_id = ? AND user_id = ?",
            )
            .bind(&survivor.project_id)
            .bind(&loser.project_id)
            .bind(&loser.owner_user_id)
            .execute(&mut *connection)
            .await?
            .rows_affected();

            let foreign_conversations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM conversations WHERE project_id = ? AND user_id <> ?",
            )
            .bind(&loser.project_id)
            .bind(&loser.owner_user_id)
            .fetch_one(&mut *connection)
            .await?;
            let foreign_teams: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM teams WHERE project_id = ? AND user_id <> ?")
                    .bind(&loser.project_id)
                    .bind(&loser.owner_user_id)
                    .fetch_one(&mut *connection)
                    .await?;
            report.foreign_children_left += (foreign_conversations + foreign_teams).max(0) as u64;

            sqlx::query("DELETE FROM project_explorer WHERE project_id = ?")
                .bind(&loser.project_id)
                .execute(&mut *connection)
                .await?;
            sqlx::query("DELETE FROM projects WHERE project_id = ?")
                .bind(&loser.project_id)
                .execute(&mut *connection)
                .await?;
            report.projects_deleted += 1;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        Database, FolderRow, IProjectStore, ProjectExplorerRow, ProjectKind, ProjectRow, SqliteProjectStore,
        init_database_memory,
    };

    async fn setup() -> (SqlitePool, Arc<dyn IProjectStore>, Database) {
        let db = init_database_memory().await.unwrap();
        let pool = db.pool().clone();
        let store: Arc<dyn IProjectStore> = Arc::new(SqliteProjectStore::new(pool.clone()));
        (pool, store, db)
    }

    async fn add_user(pool: &SqlitePool, id: &str) {
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

    async fn drift_entry(pool: &SqlitePool, pe_id: &str, owner: &str) {
        sqlx::query("UPDATE project_explorer SET owner_user_id = ? WHERE pe_id = ?")
            .bind(owner)
            .bind(pe_id)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn add_conversation(pool: &SqlitePool, id: &str, user_id: &str, project_id: &str, updated_at: i64) {
        sqlx::query(
            "INSERT INTO conversations (id, user_id, name, type, status, created_at, updated_at, project_id) \
             VALUES (?, ?, ?, 'acp', 'pending', ?, ?, ?)",
        )
        .bind(id)
        .bind(user_id)
        .bind(id)
        .bind(updated_at)
        .bind(updated_at)
        .bind(project_id)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn owner_of(pool: &SqlitePool, pe_id: &str) -> String {
        sqlx::query_scalar("SELECT owner_user_id FROM project_explorer WHERE pe_id = ?")
            .bind(pe_id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn scalar(pool: &SqlitePool, sql: &str) -> i64 {
        sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
    }

    /// Build the real-world duplicate: project A owns the folder, its binding
    /// drifts to a second user, then project B is created for the same folder
    /// because the drifted binding is invisible to `system_default_user`.
    async fn duplicate_pair(
        pool: &SqlitePool,
        store: &Arc<dyn IProjectStore>,
    ) -> (ProjectRow, ProjectExplorerRow, ProjectRow, ProjectExplorerRow, FolderRow) {
        add_user(pool, "user_drift").await;
        let folder = store.upsert_folder("file:///ws", "file:///ws").await.unwrap();
        let (old_project, old_entry) = store
            .create_project_with_workspace_entry("system_default_user", &folder.folder_id, "old", ProjectKind::Standard)
            .await
            .unwrap();
        drift_entry(pool, &old_entry.pe_id, "user_drift").await;
        let (new_project, new_entry) = store
            .create_project_with_workspace_entry("system_default_user", &folder.folder_id, "new", ProjectKind::Standard)
            .await
            .unwrap();
        (old_project, old_entry, new_project, new_entry, folder)
    }

    #[tokio::test]
    async fn clean_database_reports_no_drift() {
        let (pool, _store, _db) = setup().await;

        let drift = detect(&pool).await.unwrap();
        assert!(drift.is_clean());
        assert_eq!(drift.projects_without_workspace, 0);
        assert_eq!(repair(&pool).await.unwrap(), ProjectScopeRepairReport::default());
    }

    #[tokio::test]
    async fn drifted_owner_is_reowned_to_project_owner() {
        let (pool, store, _db) = setup().await;
        add_user(&pool, "user_drift").await;
        let folder = store.upsert_folder("file:///ws", "file:///ws").await.unwrap();
        let (project, entry) = store
            .create_project_with_workspace_entry("system_default_user", &folder.folder_id, "ws", ProjectKind::Standard)
            .await
            .unwrap();
        drift_entry(&pool, &entry.pe_id, "user_drift").await;

        assert_eq!(detect(&pool).await.unwrap().owner_mismatch, 1);

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.entries_reowned, 1);
        assert_eq!(owner_of(&pool, &entry.pe_id).await, "system_default_user");
        assert_eq!(detect(&pool).await.unwrap().owner_mismatch, 0);
        assert!(store
            .get_project("system_default_user", &project.project_id)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn duplicate_projects_merge_into_most_recently_active() {
        let (pool, store, _db) = setup().await;
        let (old_project, _old_entry, new_project, new_entry, _folder) = duplicate_pair(&pool, &store).await;
        add_conversation(&pool, "c_old", "system_default_user", &old_project.project_id, 100).await;
        add_conversation(&pool, "c_new", "system_default_user", &new_project.project_id, 200).await;

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.duplicate_groups_merged, 1);
        assert_eq!(report.projects_deleted, 1);
        assert_eq!(report.conversations_repointed, 1);

        assert_eq!(scalar(&pool, "SELECT COUNT(*) FROM projects").await, 1);
        assert!(store
            .get_project("system_default_user", &old_project.project_id)
            .await
            .unwrap()
            .is_none());
        let old_conversation_project: String =
            sqlx::query_scalar("SELECT project_id FROM conversations WHERE id = 'c_old'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(old_conversation_project, new_project.project_id);
        assert_eq!(scalar(&pool, "SELECT COUNT(*) FROM project_explorer").await, 1);
        assert_eq!(owner_of(&pool, &new_entry.pe_id).await, "system_default_user");
    }

    #[tokio::test]
    async fn orphan_explorer_rows_are_deleted() {
        let (pool, store, _db) = setup().await;
        let folder = store.upsert_folder("file:///ws", "file:///ws").await.unwrap();
        let (project, _entry) = store
            .create_project_with_workspace_entry("system_default_user", &folder.folder_id, "ws", ProjectKind::Standard)
            .await
            .unwrap();
        sqlx::query("DELETE FROM projects WHERE project_id = ?")
            .bind(&project.project_id)
            .execute(&pool)
            .await
            .unwrap();

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.orphan_entries_deleted, 1);
        assert_eq!(scalar(&pool, "SELECT COUNT(*) FROM project_explorer").await, 0);
    }

    #[tokio::test]
    async fn foreign_owned_children_are_not_moved() {
        let (pool, store, _db) = setup().await;
        let (old_project, _old_entry, new_project, _new_entry, _folder) = duplicate_pair(&pool, &store).await;
        add_user(&pool, "user_foreign").await;
        add_conversation(&pool, "c_old", "system_default_user", &old_project.project_id, 100).await;
        add_conversation(&pool, "c_new", "system_default_user", &new_project.project_id, 200).await;
        add_conversation(&pool, "c_foreign", "user_foreign", &old_project.project_id, 150).await;

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.foreign_children_left, 1);
        let foreign_project: String =
            sqlx::query_scalar("SELECT project_id FROM conversations WHERE id = 'c_foreign'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(foreign_project, old_project.project_id);
    }

    #[tokio::test]
    async fn merge_moves_or_drops_attached_entries() {
        let (pool, store, _db) = setup().await;
        let (old_project, _old_entry, new_project, _new_entry, _folder) = duplicate_pair(&pool, &store).await;
        let shared = store.upsert_folder("file:///shared", "file:///shared").await.unwrap();
        let old_only = store.upsert_folder("file:///old-only", "file:///old-only").await.unwrap();
        store
            .insert_attached_entry("system_default_user", &old_project.project_id, &shared.folder_id, Some("Shared"), 1)
            .await
            .unwrap();
        store
            .insert_attached_entry("system_default_user", &new_project.project_id, &shared.folder_id, Some("Shared"), 1)
            .await
            .unwrap();
        store
            .insert_attached_entry(
                "system_default_user",
                &old_project.project_id,
                &old_only.folder_id,
                Some("OldOnly"),
                2,
            )
            .await
            .unwrap();
        add_conversation(&pool, "c_old", "system_default_user", &old_project.project_id, 100).await;
        add_conversation(&pool, "c_new", "system_default_user", &new_project.project_id, 200).await;

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.attached_entries_dropped, 1);
        assert_eq!(report.attached_entries_moved, 1);
        let entries = store
            .list_entries("system_default_user", &new_project.project_id)
            .await
            .unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().any(|(entry, _)| entry.display_name.as_deref() == Some("OldOnly")));
    }

    #[tokio::test]
    async fn project_without_workspace_is_reported_not_deleted() {
        let (pool, _store, _db) = setup().await;
        sqlx::query(
            "INSERT INTO projects (project_id, user_id, name, kind, created_at, updated_at) \
             VALUES ('project_no_ws', 'system_default_user', 'no-ws', 'standard', 1, 1)",
        )
        .execute(&pool)
        .await
        .unwrap();

        let drift = detect(&pool).await.unwrap();
        assert!(drift.is_clean());
        assert_eq!(drift.projects_without_workspace, 1);

        let report = repair(&pool).await.unwrap();
        assert_eq!(report.projects_without_workspace, 1);
        assert_eq!(scalar(&pool, "SELECT COUNT(*) FROM projects").await, 1);
    }

    #[tokio::test]
    async fn repair_is_idempotent() {
        let (pool, store, _db) = setup().await;
        let (old_project, _old_entry, new_project, _new_entry, _folder) = duplicate_pair(&pool, &store).await;
        add_conversation(&pool, "c_old", "system_default_user", &old_project.project_id, 100).await;
        add_conversation(&pool, "c_new", "system_default_user", &new_project.project_id, 200).await;

        let first = repair(&pool).await.unwrap();
        assert!(first.projects_deleted >= 1);
        assert!(detect(&pool).await.unwrap().is_clean());
        assert_eq!(repair(&pool).await.unwrap(), ProjectScopeRepairReport::default());
    }
}
