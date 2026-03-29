# crypsol_logger

Structured, production-grade async logger for Rust services — with **CloudWatch**, **HTTP push** (Loki / Elasticsearch / custom), **file**, and **console** backends.

## Features

- Structured JSON logging with key-value fields
- 4 backends: CloudWatch, HTTP push, local files, console
- Automatic batching with configurable size & timeout
- Loki, JSON, and NDJSON output formats
- Basic Auth for authenticated endpoints (Grafana Cloud, etc.)
- Custom labels for log aggregation
- Thread-safe, high-performance design
- Minimal configuration — just set env vars
- Compile only what you use via feature flags

## Installation

Add to your `Cargo.toml`:

```toml
# Default: console + file logging
crypsol_logger = "0.3.5"

# Console only (fastest compile)
crypsol_logger = { version = "0.3.5", default-features = false, features = ["console"] }

# With CloudWatch
crypsol_logger = { version = "0.3.5", features = ["cloudwatch"] }

# With HTTP push (Loki, Elasticsearch, etc.)
crypsol_logger = { version = "0.3.5", features = ["http"] }

# Everything
crypsol_logger = { version = "0.3.5", features = ["console", "file", "cloudwatch", "http"] }
```

The `Level` enum is re-exported, so there's no need to add the `log` crate separately.

### Feature Flags

| Feature | Default | Pulls in | Description |
|---------|---------|----------|-------------|
| `console` | Yes | — | Colored stdout logging |
| `file` | Yes | — | Local file logging with retention |
| `cloudwatch` | No | `aws-config`, `aws-sdk-cloudwatchlogs` | AWS CloudWatch Logs |
| `http` | No | `reqwest`, `base64` | HTTP push (Loki, Elasticsearch, custom) |

> **Note:** Backends are checked at runtime via env vars (`LOG_TO_FILE`, `LOG_TO_HTTP`, etc.).
> Enabling a feature compiles the backend code; the env var activates it.
> If no env var is set, logs go to console (stdout) by default.

## Usage

```rust
use crypsol_logger::{Level, log};

log!(Level::Info, "This is an info message");
log!(Level::Error, "This is an error message");
log!(Level::Debug, "Debugging information");
```

Attach structured key-value fields with `;` separator:

```rust
log!(Level::Info, "User {} logged in", user_id; "ip" => ip_addr, "role" => role);
log!(Level::Error, "payment failed"; "order_id" => order_id, "amount" => amount);

// Use `=> ?` to format values using the Debug trait (Option, Result, structs, etc.)
log!(Level::Error, "query failed"; "component" => "DB", "error" => ? db_error);
```

Produces JSON:

```json
{"message":"User 42 logged in","ip":"10.0.0.1","role":"admin"}
```

Custom log stream:

```rust
log_custom!(Level::Info, "Payments", "charge created"; "tx" => tx_hash, "total" => total);
```

## Environment Variables

### Backend Selection

Backends are checked in order: CloudWatch > HTTP > File > Console.
The first enabled backend wins.

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_TO_CLOUDWATCH` | `false` | Push logs to AWS CloudWatch (requires `cloudwatch` feature) |
| `LOG_TO_HTTP` | `false` | Push logs via HTTP (requires `http` feature) |
| `LOG_TO_FILE` | `false` | Write logs to local disk files (requires `file` feature) |
| `LOG_SHOW_LOCATION` | `false` | Include `file:line` in output |
| `LOG_GROUP` | `default` | Service identifier (Loki job / CloudWatch group / file dir) |

> `AWS_LOG_GROUP` is still supported as a fallback for backward compatibility.

> If none are enabled, logs print to console (stdout).

### CloudWatch Backend

Requires `features = ["cloudwatch"]` and `LOG_TO_CLOUDWATCH=true`.

| Variable | Default | Required |
|----------|---------|----------|
| `CLOUDWATCH_AWS_ACCESS_KEY` | — | Yes |
| `CLOUDWATCH_AWS_SECRET_KEY` | — | Yes |
| `CLOUDWATCH_AWS_REGION` | `us-east-1` | Yes |
| `LOG_GROUP` | `default` | Yes |
| `LOG_BATCH_SIZE` | `10` | — |
| `BATCH_TIMEOUT` | `5` (secs) | — |

### HTTP Push Backend

Requires `features = ["http"]` and `LOG_TO_HTTP=true`.

| Variable | Default | Required |
|----------|---------|----------|
| `LOG_HTTP_ENDPOINT` | `http://localhost:3100/loki/api/v1/push` | Yes |
| `LOG_HTTP_FORMAT` | `loki` | — |
| `LOG_HTTP_BATCH_SIZE` | `10` | — |
| `LOG_HTTP_TIMEOUT_SECS` | `5` | — |
| `LOG_HTTP_LABELS` | — | — |
| `LOG_HTTP_AUTH_USER` | — | — |
| `LOG_HTTP_AUTH_TOKEN` | — | — |

**Supported formats:**

| Format | Compatible With | Example Endpoint |
|--------|----------------|------------------|
| `loki` | Grafana Loki | `http://loki:3100/loki/api/v1/push` |
| `json` | Custom APIs, Logstash | `http://logserver:8080/logs` |
| `ndjson` | Elasticsearch, OpenSearch | `http://es:9200/logs/_bulk` |

**Custom labels** (optional): `LOG_HTTP_LABELS=env=production,service=my-api`

**Basic Auth** (optional): Set `LOG_HTTP_AUTH_USER` and `LOG_HTTP_AUTH_TOKEN` to enable
`Authorization: Basic` header on every request. Required for Grafana Cloud and any
authenticated Loki/Elasticsearch endpoint.

### File Backend

Enabled by default (part of `file` feature). Activate with `LOG_TO_FILE=true`.

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_FILE_DIR` | `logs` | Directory path for log files |
| `LOG_RETENTION_DAYS` | `30` | Days to keep log files |
| `LOG_RETENTION_SIZE_MB` | `512` | Max total size before cleanup |
| `LOG_DELETE_BATCH_MB` | `100` | Amount deleted when limit is hit |

## Quick Start Examples

### Console only (no env vars needed)
```toml
crypsol_logger = "0.3.5"
```
```rust
crypsol_logger::logs::initialize_logs();
log!(Level::Info, "running in console mode");
```

### Loki (local)
```toml
crypsol_logger = { version = "0.3.5", features = ["http"] }
```
```env
LOG_TO_HTTP=true
LOG_HTTP_ENDPOINT=http://localhost:3100/loki/api/v1/push
LOG_HTTP_FORMAT=loki
LOG_GROUP=my_service
```

### Grafana Cloud (Loki)
```toml
crypsol_logger = { version = "0.3.5", features = ["http"] }
```
```env
LOG_TO_HTTP=true
LOG_HTTP_ENDPOINT=https://logs-prod-XXX.grafana.net/loki/api/v1/push
LOG_HTTP_FORMAT=loki
LOG_GROUP=my_service
LOG_HTTP_AUTH_USER=123456
LOG_HTTP_AUTH_TOKEN=glc_eyJ...
```

### Elasticsearch
```toml
crypsol_logger = { version = "0.3.5", features = ["http"] }
```
```env
LOG_TO_HTTP=true
LOG_HTTP_ENDPOINT=http://elasticsearch:9200/logs/_bulk
LOG_HTTP_FORMAT=ndjson
LOG_GROUP=my_service
```

### CloudWatch
```toml
crypsol_logger = { version = "0.3.5", features = ["cloudwatch"] }
```
```env
LOG_TO_CLOUDWATCH=true
CLOUDWATCH_AWS_ACCESS_KEY=AKIA...
CLOUDWATCH_AWS_SECRET_KEY=JdOT...
CLOUDWATCH_AWS_REGION=us-east-1
LOG_GROUP=my_service
```

### Local File
```toml
crypsol_logger = "0.3.5"
```
```env
LOG_TO_FILE=true
LOG_FILE_DIR=logs
LOG_GROUP=my_service
```

## Migrating from 0.3.x

Default features changed. If you were using CloudWatch or HTTP backends, add the required feature:

```diff
# CloudWatch users
-crypsol_logger = "0.3"
+crypsol_logger = { version = "0.3.5", features = ["cloudwatch"] }

# Loki / Elasticsearch users
-crypsol_logger = "0.3"
+crypsol_logger = { version = "0.3.5", features = ["http"] }
```

If you were only using console or file logging, just update the version:

```diff
-crypsol_logger = "0.3"
+crypsol_logger = "0.3.5"
```

No code changes required in any case — only `Cargo.toml`.

## Runtime Requirements

This crate relies on Tokio for all async backends (CloudWatch, HTTP, File).
The `log!` and `log_custom!` macros call `tokio::spawn` internally, so the
calling code must be running inside a Tokio runtime. In practice this means
your binary needs `#[tokio::main]` or an equivalent runtime handle.

The console fallback (when no backend is enabled) does not require Tokio.

## Reliability and Delivery

All backends operate on an **at-most-once** delivery model. A log entry is
formatted and dispatched to a bounded async channel; if the backend fails
to deliver it, the entry is lost.

Per-backend failure behavior:

**CloudWatch** retries on AWS `ThrottlingException` (up to 3 attempts with
exponential backoff) and once on `InvalidSequenceTokenException`. Other
errors are logged to stderr and the entry is dropped. If the initial
credential verification fails at startup, all subsequent CloudWatch log
calls return immediately without sending.

**HTTP** (Loki, Elasticsearch, custom) does not retry. Non-2xx responses
and network errors are printed to stderr and the batch is discarded.

**File** returns IO errors to the caller, but the macros discard those
errors internally, so a disk-full or permission-denied condition results
in silent loss.

**Console** writes to stdout synchronously and does not go through the
async channel.

Ordering is preserved within a single log stream and batch, but concurrent
batches may arrive out of order at the backend.

## Operational Limits

Both CloudWatch and HTTP backends buffer log entries through a bounded
Tokio MPSC channel with a fixed capacity of **1000 entries**. If the
backend cannot keep up with the emission rate, the channel fills and
subsequent `log!` calls will await until space opens up. This means
sustained logging pressure with a slow or unreachable backend can
introduce latency into your application's async tasks.

Batch size and flush timeout are tunable per backend via environment
variables (see above). Larger batches reduce network calls at the cost
of higher per-flush latency and memory usage. Smaller batches provide
more frequent delivery but increase overhead.

For high-throughput services (above 1k logs/sec), consider increasing
`LOG_HTTP_BATCH_SIZE` / `LOG_BATCH_SIZE` and adjusting the timeout to
match your latency tolerance.

## License

MIT &copy; 2025 [Crypsol](https://crypsol.tech/)