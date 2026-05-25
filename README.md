AvaKs

AvaKs is a lightweight cross-platform filesystem indexing and monitoring daemon written in Rust.

Features

- Full filesystem crawl
- Real-time filesystem monitoring
- SQLite indexing database
- JSON HTTP API
- Hourly rotating logs
- Fuzzy search
- Malware pattern detection
- Linux/macOS/Windows support
- Single-file implementation

Build

cargo build --release

Run

cargo run --release

Commands

avaks help
avaks version
avaks run

API

GET /fuzzy/<query>
GET /file/<path_or_id>
GET /events?from=0&to=9999999999
GET /alerts/recent

Database

~/.avaks/index.db

Logs

~/.avaks/logs/

License

BSD 3-Clause License
