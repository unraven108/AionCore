//! Transcript preamble for a CodeBuddy account-failover replay.
//!
//! A failover clears the persisted ACP session id: the previous session lives
//! under the old account's `CODEBUDDY_CONFIG_DIR` and cannot be resumed by the
//! next account. The replay that follows would therefore reach a fresh agent
//! with only the current prompt — a bare "continue" loses its meaning.
//!
//! This module rebuilds the visible text history into one bounded preamble so
//! the new session starts with the same context the user sees in the UI.

use aionui_db::{IConversationRepository, MessagePageDirection, MessagePageParams};
use tracing::{info, warn};

/// Newest messages considered for the preamble.
const MAX_MESSAGES: u32 = 40;
/// Upper bound on the rendered preamble. Keeps a long conversation from
/// consuming the whole context window on the first reopened turn.
const MAX_CHARS: usize = 12_000;

/// Build the `[Previous Conversation]` block for a failover replay.
///
/// Returns `None` when the conversation has no usable prior text, so a switch
/// on a brand-new conversation replays the original prompt untouched.
pub(crate) async fn build_replay_context(
    repo: &dyn IConversationRepository,
    user_id: &str,
    conversation_id: &str,
    exclude_message_id: Option<&str>,
) -> Option<String> {
    let page = match repo
        .list_messages_page(
            user_id,
            conversation_id,
            &MessagePageParams {
                limit: MAX_MESSAGES,
                direction: MessagePageDirection::InitialLatest,
            },
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            warn!(
                user_id,
                conversation_id,
                error = %error,
                "failover replay: failed to read conversation history"
            );
            return None;
        }
    };

    let mut lines: Vec<String> = Vec::new();
    let mut used_chars = 0usize;

    // Walk backwards so the newest context wins the character budget.
    for row in page.items.iter().rev() {
        if Some(row.id.as_str()) == exclude_message_id {
            continue;
        }
        if row.hidden || row.r#type != "text" || row.status.as_deref() == Some("work") {
            continue;
        }
        let role = match row.position.as_deref() {
            Some("right") => "User",
            Some("left") => "Assistant",
            _ => continue,
        };
        let Ok(content) = serde_json::from_str::<serde_json::Value>(&row.content) else {
            continue;
        };
        let Some(text) = content.get("content").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let text = text.trim();
        if text.is_empty() {
            continue;
        }

        let line = format!("{role}: {text}");
        let line_chars = line.chars().count();
        if used_chars + line_chars > MAX_CHARS {
            if lines.is_empty() {
                lines.push(line.chars().take(MAX_CHARS).collect());
            }
            break;
        }
        used_chars += line_chars;
        lines.push(line);
    }

    if lines.is_empty() {
        return None;
    }
    lines.reverse();

    let context = format!(
        "[Previous Conversation]\n{}\n[/Previous Conversation]",
        lines.join("\n")
    );
    info!(
        conversation_id,
        history_messages = lines.len(),
        history_chars = context.chars().count(),
        "failover replay: carrying visible history into the fresh session"
    );
    Some(context)
}
