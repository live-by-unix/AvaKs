# AvaKs

AvaKs is a lightweight cross-platform filesystem indexing and monitoring daemon written in Rust.

## Features

- Full filesystem crawl
- Real-time filesystem monitoring
- SQLite indexing database
- JSON HTTP API
- Hourly rotating logs
- Fuzzy search
- Malware pattern detection
- Linux/macOS/Windows support
- Single-file implementation

## Build
```bash
git clone https://github.com/live-by-unix/avaks.git
cargo build --release
```

## Run
```bash
cargo run --release
```

## Commands
```bash
avaks help
avaks version
avaks run
```

## API

GET /fuzzy/<query>
GET /file/<path_or_id>
GET /events?from=0&to=9999999999
GET /alerts/recent

## Database
```text
~/.avaks/index.db
```

## Logs
```text
~/.avaks/logs/
```

## License

BSD 3-Clause License
