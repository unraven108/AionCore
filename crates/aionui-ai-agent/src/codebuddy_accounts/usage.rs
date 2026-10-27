//! Today's credit spend per CodeBuddy account.
//!
//! CodeBuddy has no balance/usage API for the CLI token (the console only
//! exposes it to a browser session), but the CLI writes every charged request
//! stage to its own transcript: `<profile>/projects/<slug>/<session>.jsonl`,
//! one line per entry, with `"type":"credit-usage"` and
//! `providerData.{credit, conversationRequestId, stageId}`. Each account runs
//! with its own `CODEBUDDY_CONFIG_DIR`, so the directory name already
//! attributes the spend to an account.
//!
//! Aggregation mirrors the CLI's own history reader: entries are keyed by
//! `(request, stage)` with the last report winning, then summed per request
//! and rounded to two decimals. Only files modified since local midnight are
//! read, and parsed files are cached by `(mtime, size)` because a busy day's
//! transcripts add up to tens of megabytes.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::UNIX_EPOCH;

use serde_json::Value;

use super::PROFILES_DIR;

/// Charge lines come in two shapes, and the CLI's own history reader sums
/// both: staged team runs write `"type":"credit-usage"` rows carrying the
/// stage total, while ordinary sessions carry the per-message figure on
/// `providerData.rawUsage.credit`. Either way the marker tells us the line is
/// worth parsing.
const CREDIT_ENTRY_MARKERS: [&str; 2] = ["\"type\":\"credit-usage\"", "\"rawUsage\""];

/// Parsed charge lines of one transcript, kept until the file changes.
struct FileUsage {
    modified_ms: i64,
    size: u64,
    day_start_ms: i64,
    /// `(request_id, stage_id)` → credit, last report wins.
    stages: HashMap<(String, String), f64>,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, FileUsage>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, FileUsage>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Local (not UTC) midnight: "today" follows the clock the user sees.
pub(crate) fn local_day_start_ms() -> i64 {
    use chrono::{Local, TimeZone};

    let now = Local::now();
    now.date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|midnight| Local.from_local_datetime(&midnight).earliest())
        .map(|start| start.timestamp_millis())
        .unwrap_or_else(|| now.timestamp_millis())
}

/// Credits spent since local midnight, keyed by account id.
///
/// Accounts without spend are omitted; callers default the missing entries
/// to zero. Sessions that ran under a per-account config dir are counted from
/// `codebuddy-accounts/<uid>/projects`, where the directory itself proves the
/// account.
///
/// Sessions in CodeBuddy's shared default config dir carry no account
/// identity. They are counted only when the machine holds a single CodeBuddy
/// credential: then every one of them necessarily ran as that account. With
/// more than one credential (the user switched accounts) the attribution is
/// unknowable, so those sessions are left out rather than charged to the
/// wrong account.
pub(crate) fn today_credits_by_account(root: &Path) -> HashMap<String, f64> {
    let day_start_ms = local_day_start_ms();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut cache = cache().lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut per_account: HashMap<String, f64> = HashMap::new();
    for data_root in data_roots(root) {
        for (uid, credits) in scan_profiles(&data_root, day_start_ms, &mut cache, &mut seen) {
            let total = per_account.entry(uid).or_default();
            *total = round_credit(*total + credits);
        }
    }

    if let Some(uid) = sole_credential_uid()
        && let Some(projects) = default_config_projects()
    {
        let credits = credits_of_projects(&projects, day_start_ms, &mut cache, &mut seen);
        if credits > 0.0 {
            let total = per_account.entry(uid).or_default();
            *total = round_credit(*total + credits);
        }
    }

    // Files deleted by CodeBuddy's own cleanup must not keep their entries.
    cache.retain(|path, _| seen.contains(path));
    per_account
}

/// The account every CodeBuddy session on this machine must have run as.
///
/// `None` when the auth dir holds credentials for more than one account: the
/// shared-config transcripts cannot be split between them, and guessing would
/// silently move credits from one account to another.
fn sole_credential_uid() -> Option<String> {
    let dir = super::auth_file::auth_dir()?;
    let mut uids: HashSet<String> = HashSet::new();
    for entry in fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(super::auth_file::AUTH_FILE_PREFIX) || !name.ends_with(".info") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if let Some(uid) = value
            .get("account")
            .and_then(|account| account.get("uid"))
            .and_then(Value::as_str)
            .filter(|uid| !uid.is_empty())
        {
            uids.insert(uid.to_owned());
        }
    }
    if uids.len() == 1 { uids.into_iter().next() } else { None }
}

/// `<home>/.codebuddy/projects`: CodeBuddy's own default config dir, used when
/// no `CODEBUDDY_CONFIG_DIR` override is in effect.
fn default_config_projects() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".codebuddy").join("projects"))
}

/// Data dirs on this machine that keep an account library.
///
/// A release build and a dev build each own a data dir (`<base>/AionUi/aionui`,
/// `<base>/AionUi-Dev/aionui`, …), so one account's sessions can be split
/// across several of them. The spend still belongs to the account, so the
/// totals are merged instead of reporting only the running instance.
fn data_roots(root: &Path) -> Vec<PathBuf> {
    let mut roots = vec![root.to_path_buf()];
    let Some(base) = root.parent().and_then(Path::parent) else {
        return roots;
    };
    let Ok(current) = fs::canonicalize(root) else {
        return roots;
    };
    let Ok(entries) = fs::read_dir(base) else {
        return roots;
    };
    for entry in entries.flatten() {
        let candidate = entry.path().join("aionui");
        if !candidate.join(PROFILES_DIR).is_dir() {
            continue;
        }
        // Case-insensitive filesystems must not let the running root in twice.
        if fs::canonicalize(&candidate).is_ok_and(|resolved| resolved == current) {
            continue;
        }
        roots.push(candidate);
    }
    roots
}

fn scan_profiles(
    root: &Path,
    day_start_ms: i64,
    cache: &mut HashMap<PathBuf, FileUsage>,
    seen: &mut HashSet<PathBuf>,
) -> HashMap<String, f64> {
    let accounts_dir = root.join(PROFILES_DIR);
    let Ok(entries) = fs::read_dir(&accounts_dir) else {
        return HashMap::new();
    };

    let mut per_account = HashMap::new();
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let account_id = entry.file_name().to_string_lossy().into_owned();
        let credits = credits_of_projects(&entry.path().join("projects"), day_start_ms, cache, seen);
        if credits > 0.0 {
            per_account.insert(account_id, credits);
        }
    }
    per_account
}

fn credits_of_projects(
    projects: &Path,
    day_start_ms: i64,
    cache: &mut HashMap<PathBuf, FileUsage>,
    seen: &mut HashSet<PathBuf>,
) -> f64 {
    let mut files = Vec::new();
    collect_transcripts(projects, day_start_ms, &mut files);

    let mut stages: HashMap<(String, String), f64> = HashMap::new();
    for file in files {
        let Ok(metadata) = fs::metadata(&file) else {
            continue;
        };
        let modified_ms = metadata
            .modified()
            .ok()
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_millis() as i64)
            .unwrap_or(0);
        let size = metadata.len();
        seen.insert(file.clone());

        let cached = cache.get(&file).is_some_and(|cached| {
            cached.modified_ms == modified_ms && cached.size == size && cached.day_start_ms == day_start_ms
        });
        let file_stages = if cached {
            cache[&file].stages.clone()
        } else {
            let parsed = parse_transcript(&file, day_start_ms);
            cache.insert(
                file.clone(),
                FileUsage {
                    modified_ms,
                    size,
                    day_start_ms,
                    stages: parsed.clone(),
                },
            );
            parsed
        };
        stages.extend(file_stages);
    }

    sum_by_request(&stages)
}

#[cfg(test)]
fn credits_by_account(root: &Path, day_start_ms: i64) -> HashMap<String, f64> {
    scan_profiles(root, day_start_ms, &mut HashMap::new(), &mut HashSet::new())
}

fn collect_transcripts(dir: &Path, since_ms: i64, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let cutoff = UNIX_EPOCH + std::time::Duration::from_millis(since_ms.max(0) as u64);
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_dir() {
            collect_transcripts(&path, since_ms, out);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }
        // A transcript last written before midnight cannot hold today's
        // charges, so old sessions are never read (a busy profile keeps
        // hundreds of them).
        let modified = entry.metadata().and_then(|metadata| metadata.modified()).ok();
        if modified.is_some_and(|at| at < cutoff) {
            continue;
        }
        out.push(path);
    }
}

fn parse_transcript(path: &Path, day_start_ms: i64) -> HashMap<(String, String), f64> {
    let mut stages = HashMap::new();
    let Ok(file) = File::open(path) else {
        return stages;
    };
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else {
            continue;
        };
        if !CREDIT_ENTRY_MARKERS.iter().any(|marker| line.contains(marker)) {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        // The entry timestamp is when the credit was charged; the file mtime
        // only tells whether the file is worth reading at all.
        let timestamp = entry.get("timestamp").and_then(Value::as_i64).unwrap_or(0);
        if timestamp < day_start_ms {
            continue;
        }
        let Some(provider) = entry.get("providerData") else {
            continue;
        };
        let Some(request_id) = provider
            .get("conversationRequestId")
            .or_else(|| provider.get("requestId"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        else {
            continue;
        };
        // Mirror `collectRequestCreditsFromHistory` in the CLI: a stage total
        // wins over the per-message figure, and re-reports of the same stage
        // or message are collapsed (last one wins).
        let staged = entry.get("type").and_then(Value::as_str) == Some("credit-usage");
        let credit = if staged {
            provider.get("credit").and_then(Value::as_f64)
        } else {
            provider
                .get("rawUsage")
                .and_then(|usage| usage.get("credit"))
                .and_then(Value::as_f64)
        };
        let Some(credit) = credit.filter(|credit| *credit > 0.0) else {
            continue;
        };
        let (prefix, id) = if staged {
            ("stage", provider.get("stageId"))
        } else {
            ("message", provider.get("messageId"))
        };
        let dedupe = id
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("#{index}"));
        stages.insert((request_id.to_owned(), format!("{prefix}:{dedupe}")), credit);
    }
    stages
}

/// Sum per request (rounded like the CLI), then total.
fn sum_by_request(stages: &HashMap<(String, String), f64>) -> f64 {
    let mut per_request: HashMap<&str, f64> = HashMap::new();
    for ((request_id, _), credit) in stages {
        *per_request.entry(request_id.as_str()).or_default() += credit;
    }
    let total: f64 = per_request.values().map(|credit| round_credit(*credit)).sum();
    round_credit(total)
}

fn round_credit(credit: f64) -> f64 {
    (credit * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_transcript(dir: &Path, name: &str, lines: &[String]) {
        fs::create_dir_all(dir).expect("create transcript dir");
        fs::write(dir.join(name), lines.join("\n")).expect("write transcript");
    }

    fn credit_line(timestamp: i64, request_id: &str, stage_id: &str, credit: f64) -> String {
        serde_json::json!({
            "timestamp": timestamp,
            "type": "credit-usage",
            "providerData": {
                "conversationRequestId": request_id,
                "stageId": stage_id,
                "credit": credit
            }
        })
        .to_string()
    }

    /// Ordinary (non-team) sessions report the charge per model call instead.
    fn raw_usage_line(timestamp: i64, request_id: &str, message_id: &str, credit: f64) -> String {
        serde_json::json!({
            "timestamp": timestamp,
            "type": "function_call",
            "providerData": {
                "conversationRequestId": request_id,
                "messageId": message_id,
                "rawUsage": { "credit": credit }
            }
        })
        .to_string()
    }

    const DAY_START: i64 = 1_700_000_000_000;

    #[test]
    fn sums_today_per_request_and_keeps_the_last_stage_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        let projects = dir.path().join("projects").join("repo");
        write_transcript(
            &projects,
            "session.jsonl",
            &[
                credit_line(DAY_START + 10, "req-1", "stage-a", 0.10),
                // Same stage re-reported with a higher figure: last wins.
                credit_line(DAY_START + 20, "req-1", "stage-a", 0.15),
                credit_line(DAY_START + 30, "req-1", "stage-b", 0.20),
                credit_line(DAY_START + 40, "req-2", "stage-a", 0.30),
                // Yesterday's charge must not leak into today.
                credit_line(DAY_START - 1, "req-0", "stage-a", 5.0),
            ],
        );

        let stages = parse_transcript(&projects.join("session.jsonl"), DAY_START);
        assert_eq!(stages.len(), 3);
        assert!((sum_by_request(&stages) - 0.65).abs() < 1e-9);
    }

    #[test]
    fn sums_per_message_usage_from_ordinary_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let projects = dir.path().join("projects").join("repo");
        write_transcript(
            &projects,
            "session.jsonl",
            &[
                raw_usage_line(DAY_START + 10, "req-1", "msg-1", 0.35),
                raw_usage_line(DAY_START + 20, "req-1", "msg-2", 0.02),
                // The same message re-reported must not be added twice.
                raw_usage_line(DAY_START + 30, "req-1", "msg-1", 0.35),
                raw_usage_line(DAY_START - 1, "req-0", "msg-0", 9.0),
            ],
        );

        let stages = parse_transcript(&projects.join("session.jsonl"), DAY_START);
        assert_eq!(stages.len(), 2);
        assert!((sum_by_request(&stages) - 0.37).abs() < 1e-9);
    }

    #[test]
    fn ignores_lines_without_a_credit_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let projects = dir.path().join("projects");
        write_transcript(
            &projects,
            "session.jsonl",
            &[
                serde_json::json!({ "timestamp": DAY_START + 1, "type": "message" }).to_string(),
                r#"{"timestamp": not json"#.to_owned(),
                credit_line(DAY_START + 2, "req-1", "stage-a", 0.0),
            ],
        );

        assert!(parse_transcript(&projects.join("session.jsonl"), DAY_START).is_empty());
    }

    #[test]
    fn totals_are_grouped_by_account_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let accounts = dir.path().join(PROFILES_DIR);
        write_transcript(
            &accounts.join("account-a").join("projects").join("repo"),
            "session.jsonl",
            &[credit_line(DAY_START + 1, "req-1", "stage-a", 0.25)],
        );
        write_transcript(
            &accounts.join("account-b").join("projects").join("repo"),
            "session.jsonl",
            &[credit_line(DAY_START + 1, "req-1", "stage-a", 1.5)],
        );
        // An account that has never run is simply absent from the map.
        fs::create_dir_all(accounts.join("account-idle")).expect("create idle account");

        let totals = credits_by_account(dir.path(), DAY_START);
        assert_eq!(totals.len(), 2);
        assert!((totals["account-a"] - 0.25).abs() < 1e-9);
        assert!((totals["account-b"] - 1.5).abs() < 1e-9);
    }

    #[test]
    fn local_day_start_is_midnight() {
        let start = local_day_start_ms();
        let now = chrono::Local::now().timestamp_millis();
        assert!(start <= now);
        // Midnight is at most 24h back plus a small clock skew allowance.
        assert!(now - start < 25 * 60 * 60 * 1000);
        assert_eq!(start % 1000, 0);
    }
}
