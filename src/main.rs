use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::get,
    Json,
    Router,
};
use chrono::{Datelike, Local, Timelike, Utc};
use fuzzy_matcher::skim::SkimMatcherV2;
use fuzzy_matcher::FuzzyMatcher;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path as FsPath, PathBuf};
use std::sync::{mpsc::channel, Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use walkdir::WalkDir;

#[derive(Clone)]
struct AppState {
    db: Arc<Mutex<Connection>>,
    matcher: Arc<SkimMatcherV2>,
    malware: Arc<Mutex<Vec<String>>>,
    cache: Arc<RwLock<Vec<FileRecord>>>,
}

#[derive(Clone, Serialize)]
struct FileRecord {
    id: i64,
    path: String,
    modified: i64,
    size: i64,
}

#[derive(Serialize)]
struct EventRecord {
    id: i64,
    kind: String,
    path: String,
    ts: i64,
}

#[derive(Serialize)]
struct AlertRecord {
    id: i64,
    path: String,
    reason: String,
    ts: i64,
}

#[derive(Deserialize)]
struct EventQuery {
    from: Option<i64>,
    to: Option<i64>,
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn avaks_dir() -> PathBuf {
    dirs::home_dir().unwrap().join(".avaks")
}

fn db_path() -> PathBuf {
    avaks_dir().join("index.db")
}

fn logs_dir() -> PathBuf {
    avaks_dir().join("logs")
}

fn malware_path() -> PathBuf {
    avaks_dir().join("malware.json")
}

fn ensure_dirs() {
    fs::create_dir_all(avaks_dir()).ok();
    fs::create_dir_all(logs_dir()).ok();
}

fn current_log_file() -> PathBuf {
    let now = Local::now();

    logs_dir().join(format!(
        "log-{:04}-{:02}-{:02}-{:02}.log",
        now.year(),
        now.month(),
        now.day(),
        now.hour()
    ))
}

fn log_line(line: &str) {
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(current_log_file())
    {
        let _ = writeln!(f, "[{}] {}", Utc::now().to_rfc3339(), line);
    }
}

fn create_tables(conn: &Connection) {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=100000;

        CREATE TABLE IF NOT EXISTS files(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE,
            modified INTEGER,
            size INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);

        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT,
            path TEXT,
            ts INTEGER
        );

        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT,
            reason TEXT,
            ts INTEGER
        );
        ",
    )
    .ok();
}

fn load_malware_rules() -> Vec<String> {
    let path = malware_path();

    if !path.exists() {
        fs::write(&path, "[]").ok();
    }

    let mut s = String::new();

    if let Ok(mut f) = File::open(path) {
        f.read_to_string(&mut s).ok();
    }

    serde_json::from_str(&s).unwrap_or_default()
}

fn check_malware(state: &AppState, path: &str) {
    let rules = state.malware.lock().unwrap().clone();

    for rule in rules {
        if path.to_lowercase().contains(&rule.to_lowercase()) {
            let conn = state.db.lock().unwrap();

            conn.execute(
                "INSERT INTO alerts(path, reason, ts) VALUES(?1, ?2, ?3)",
                params![path, format!("matched {}", rule), now_ts()],
            )
            .ok();

            log_line(&format!("alert {} {}", path, rule));
        }
    }
}

fn refresh_cache(state: &AppState) {
    let conn = state.db.lock().unwrap();

    let mut stmt = conn
        .prepare("SELECT id, path, modified, size FROM files")
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok(FileRecord {
                id: row.get(0)?,
                path: row.get(1)?,
                modified: row.get(2)?,
                size: row.get(3)?,
            })
        })
        .unwrap();

    let mut cache = Vec::new();

    for row in rows.flatten() {
        cache.push(row);
    }

    *state.cache.write().unwrap() = cache;
}

fn insert_file(state: &AppState, path: &str) {
    if let Ok(meta) = fs::metadata(path) {
        let modified = meta
            .modified()
            .unwrap_or(SystemTime::now())
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let size = meta.len() as i64;

        let conn = state.db.lock().unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO files(path, modified, size) VALUES(?1, ?2, ?3)",
            params![path, modified, size],
        )
        .ok();

        check_malware(state, path);
    }
}

fn remove_file(state: &AppState, path: &str) {
    let conn = state.db.lock().unwrap();

    conn.execute(
        "DELETE FROM files WHERE path=?1",
        params![path]
    )
    .ok();
}

fn add_event(state: &AppState, kind: &str, path: &str) {
    let conn = state.db.lock().unwrap();

    conn.execute(
        "INSERT INTO events(kind, path, ts) VALUES(?1, ?2, ?3)",
        params![kind, path, now_ts()],
    )
    .ok();
}

fn roots() -> Vec<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let mut drives = Vec::new();

        for c in b'A'..=b'Z' {
            let d = format!("{}:\\", c as char);

            if FsPath::new(&d).exists() {
                drives.push(PathBuf::from(d));
            }
        }

        drives
    }

    #[cfg(not(target_os = "windows"))]
    {
        vec![
            PathBuf::from("/"),
            dirs::home_dir().unwrap_or(PathBuf::from("/home")),
            PathBuf::from("/mnt"),
            PathBuf::from("/media"),
            PathBuf::from("/run/media"),
            PathBuf::from("/opt"),
            PathBuf::from("/srv"),
            PathBuf::from("/var"),
        ]
    }
}

fn initial_scan(state: AppState) {
    let mut scanned = 0u64;

    for root in roots() {
        if !root.exists() {
            continue;
        }

        log_line(&format!("scan root {}", root.display()));

        for entry in WalkDir::new(root)
            .follow_links(false)
            .same_file_system(false)
            .into_iter()
        {
            let entry = match entry {
                Ok(v) => v,
                Err(_) => continue,
            };

            let path = entry.path().to_string_lossy().to_string();

            insert_file(&state, &path);

            scanned += 1;

            if scanned % 10000 == 0 {
                log_line(&format!("indexed {}", scanned));
            }
        }
    }

    refresh_cache(&state);

    log_line(&format!("scan complete {}", scanned));
}

fn handle_event(state: &AppState, event: Event) {
    let kind = match event.kind {
        EventKind::Create(_) => "create",
        EventKind::Modify(_) => "modify",
        EventKind::Remove(_) => "delete",
        EventKind::Access(_) => "access",
        _ => "other",
    };

    for path in event.paths {
        let p = path.to_string_lossy().to_string();

        if kind == "delete" {
            remove_file(state, &p);
        } else {
            insert_file(state, &p);
        }

        add_event(state, kind, &p);
    }
}

fn start_watcher(state: AppState) {
    thread::spawn(move || {
        let (tx, rx) = channel();

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                tx.send(res).ok();
            },
            Config::default(),
        )
        .unwrap();

        for root in roots() {
            if root.exists() {
                watcher.watch(&root, RecursiveMode::Recursive).ok();
            }
        }

        loop {
            match rx.recv() {
                Ok(Ok(event)) => handle_event(&state, event),
                Ok(Err(e)) => log_line(&format!("watch error {}", e)),
                Err(_) => break,
            }
        }
    });
}

async fn root() -> impl IntoResponse {
    Json(json!({
        "name":"AvaKs",
        "version":"1.0.0",
        "status":"online",
        "port":6090
    }))
}

async fn fuzzy(
    Path(query): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let cache = state.cache.read().unwrap();

    let q = query.to_lowercase();

    let mut scored = Vec::new();

    for file in cache.iter() {
        if file.path.to_lowercase().contains(&q) {
            scored.push((999999, file.clone()));
            continue;
        }

        if let Some(score) = state.matcher.fuzzy_match(&file.path, &query) {
            scored.push((score, file.clone()));
        }
    }

    scored.sort_by(|a, b| b.0.cmp(&a.0));

    Json(json!(
        scored
            .into_iter()
            .take(200)
            .map(|x| x.1)
            .collect::<Vec<_>>()
    ))
}

async fn file(
    Path(path_or_id): Path<String>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let cache = state.cache.read().unwrap();

    if let Ok(id) = path_or_id.parse::<i64>() {
        for file in cache.iter() {
            if file.id == id {
                return Json(json!(file));
            }
        }
    } else {
        for file in cache.iter() {
            if file.path == path_or_id {
                return Json(json!(file));
            }
        }
    }

    Json(json!({"error":"not found"}))
}

async fn events(
    Query(q): Query<EventQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let from = q.from.unwrap_or(0);
    let to = q.to.unwrap_or(i64::MAX);

    let conn = state.db.lock().unwrap();

    let mut stmt = conn
        .prepare(
            "SELECT id, kind, path, ts FROM events WHERE ts>=?1 AND ts<=?2 ORDER BY ts DESC LIMIT 1000",
        )
        .unwrap();

    let rows = stmt
        .query_map(params![from, to], |row| {
            Ok(EventRecord {
                id: row.get(0)?,
                kind: row.get(1)?,
                path: row.get(2)?,
                ts: row.get(3)?,
            })
        })
        .unwrap();

    Json(json!(rows.flatten().collect::<Vec<_>>()))
}

async fn alerts_recent(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let conn = state.db.lock().unwrap();

    let mut stmt = conn
        .prepare(
            "SELECT id, path, reason, ts FROM alerts ORDER BY ts DESC LIMIT 100",
        )
        .unwrap();

    let rows = stmt
        .query_map([], |row| {
            Ok(AlertRecord {
                id: row.get(0)?,
                path: row.get(1)?,
                reason: row.get(2)?,
                ts: row.get(3)?,
            })
        })
        .unwrap();

    Json(json!(rows.flatten().collect::<Vec<_>>()))
}

async fn stats(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let cache = state.cache.read().unwrap();

    Json(json!({
        "indexed_files": cache.len(),
        "status": "healthy"
    }))
}

async fn run_server(state: AppState) {
    let app = Router::new()
        .route("/", get(root))
        .route("/stats", get(stats))
        .route("/fuzzy/:query", get(fuzzy))
        .route("/file/:path_or_id", get(file))
        .route("/events", get(events))
        .route("/alerts/recent", get(alerts_recent))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:6090")
        .await
        .unwrap();

    println!("AvaKs running on http://127.0.0.1:6090");
    println!("Stats: http://127.0.0.1:6090/stats");

    axum::serve(listener, app).await.unwrap();
}

fn help() {
    println!("AvaKs 1.0.0");
    println!("Commands:");
    println!("  help");
    println!("  version");
    println!("  run");
}

fn version() {
    println!("AvaKs 1.0.0");
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() > 1 {
        match args[1].as_str() {
            "help" | "--help" | "-h" => {
                help();
                return;
            }
            "version" | "--version" | "-v" => {
                version();
                return;
            }
            _ => {}
        }
    }

    ensure_dirs();

    let conn = Connection::open(db_path()).unwrap();

    create_tables(&conn);

    let state = AppState {
        db: Arc::new(Mutex::new(conn)),
        matcher: Arc::new(SkimMatcherV2::default()),
        malware: Arc::new(Mutex::new(load_malware_rules())),
        cache: Arc::new(RwLock::new(Vec::new())),
    };

    let scan_state = state.clone();

    thread::spawn(move || {
        initial_scan(scan_state);
    });

    start_watcher(state.clone());

    let refresh_state = state.clone();

    thread::spawn(move || {
        loop {
            refresh_cache(&refresh_state);
            thread::sleep(Duration::from_secs(30));
        }
    });

    let malware_state = state.clone();

    thread::spawn(move || {
        loop {
            let rules = load_malware_rules();
            *malware_state.malware.lock().unwrap() = rules;
            thread::sleep(Duration::from_secs(60));
        }
    });

    log_line("AvaKs started");

    run_server(state).await;
}
