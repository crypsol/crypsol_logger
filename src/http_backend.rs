use std::env;

use chrono::Utc;
use once_cell::sync::Lazy;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::logs::{LogStream, format_log_entry};

/// URL to push logs to (e.g. `http://loki:3100/loki/api/v1/push`).
static HTTP_ENDPOINT: Lazy<String> = Lazy::new(|| {
    env::var("LOG_HTTP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:3100/loki/api/v1/push".into())
});

/// Payload format: `loki`, `json`, or `ndjson`.
static HTTP_FORMAT: Lazy<HttpLogFormat> = Lazy::new(|| {
    match env::var("LOG_HTTP_FORMAT")
        .unwrap_or_else(|_| "loki".into())
        .to_lowercase()
        .as_str()
    {
        "json" => HttpLogFormat::Json,
        "ndjson" => HttpLogFormat::Ndjson,
        _ => HttpLogFormat::Loki,
    }
});

/// Batch size before flushing.
static HTTP_BATCH_SIZE: Lazy<usize> = Lazy::new(|| {
    env::var("LOG_HTTP_BATCH_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
});

/// Batch timeout in seconds.
static HTTP_BATCH_TIMEOUT: Lazy<std::time::Duration> = Lazy::new(|| {
    env::var("LOG_HTTP_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
        .unwrap_or(std::time::Duration::from_secs(5))
});

/// Extra labels attached to every log entry (parsed from `key1=val1,key2=val2`).
static HTTP_LABELS: Lazy<Vec<(String, String)>> = Lazy::new(|| {
    env::var("LOG_HTTP_LABELS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, val))
            }
        })
        .collect()
});

/// The service/job name used in Loki stream labels. Falls back to `AWS_LOG_GROUP`
/// then `"default"` so there is always a meaningful label.
static HTTP_JOB: Lazy<String> =
    Lazy::new(|| env::var("AWS_LOG_GROUP").unwrap_or_else(|_| "default".into()));

/// Shared HTTP client — reuse connections.
static HTTP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(2)
        .build()
        .expect("Failed to build HTTP client")
});

/// Payload format for the HTTP backend.
enum HttpLogFormat {
    Loki,
    Json,
    Ndjson,
}

/// A single log entry queued for HTTP push.
pub struct HttpLogItem {
    pub level: String,
    pub message: String,
    pub stream: String,
    pub timestamp_ns: String,
}

/// Static channel for batching HTTP log items.
static HTTP_BATCH_SENDER: Lazy<mpsc::Sender<HttpLogItem>> = Lazy::new(|| {
    let (tx, rx) = mpsc::channel::<HttpLogItem>(1000);
    tokio::spawn(async move {
        process_http_batches(rx).await;
    });
    tx
});

/// Queues a log entry for HTTP push. Called from the `log!` / `log_custom!` macros.
pub async fn queue_http_log(
    level: log::Level,
    message: &str,
    log_stream: LogStream,
    file: &str,
    line: u32,
) {
    let entry = format_log_entry(level, message, file, line);
    let now = Utc::now();
    let item = HttpLogItem {
        level: level.as_str().to_lowercase(),
        message: entry,
        stream: log_stream.as_str_pub().to_string(),
        timestamp_ns: format!("{}", now.timestamp_nanos_opt().unwrap_or(0)),
    };
    if let Err(e) = HTTP_BATCH_SENDER.send(item).await {
        eprintln!("Failed to enqueue HTTP log: {e}");
    }
}

/// Background task that batches log items and flushes them via HTTP.
async fn process_http_batches(mut rx: mpsc::Receiver<HttpLogItem>) {
    use tokio::time;

    let mut batch: Vec<HttpLogItem> = Vec::new();
    let mut interval = time::interval(*HTTP_BATCH_TIMEOUT);

    loop {
        tokio::select! {
            maybe_item = rx.recv() => {
                if let Some(item) = maybe_item {
                    batch.push(item);
                    if batch.len() >= *HTTP_BATCH_SIZE {
                        let items = std::mem::take(&mut batch);
                        tokio::spawn(push_batch(items));
                    }
                } else {
                    break;
                }
            },
            _ = interval.tick() => {
                if !batch.is_empty() {
                    let items = std::mem::take(&mut batch);
                    tokio::spawn(push_batch(items));
                }
            },
        }
    }

    if !batch.is_empty() {
        let _ = push_batch(batch).await;
    }
}

/// Formats the batch according to `LOG_HTTP_FORMAT` and POSTs it to `LOG_HTTP_ENDPOINT`.
async fn push_batch(items: Vec<HttpLogItem>) {
    let (body, content_type) = match *HTTP_FORMAT {
        HttpLogFormat::Loki => (format_loki(&items), "application/json"),
        HttpLogFormat::Json => (format_json(&items), "application/json"),
        HttpLogFormat::Ndjson => (format_ndjson(&items), "application/x-ndjson"),
    };

    match HTTP_CLIENT
        .post(HTTP_ENDPOINT.as_str())
        .header("Content-Type", content_type)
        .body(body)
        .send()
        .await
    {
        Ok(resp) if !resp.status().is_success() => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let preview = if body.len() > 200 {
                &body[..200]
            } else {
                &body
            };
            eprintln!("HTTP log push returned {status}: {preview}");
        }
        Err(e) => {
            eprintln!("HTTP log push failed: {e}");
        }
        _ => {}
    }
}

// ─── Format adapters ────────────────────────────────────────────────

/// Grafana Loki push format: `{"streams":[{"stream":{...},"values":[...]}]}`
fn format_loki(items: &[HttpLogItem]) -> String {
    use std::collections::HashMap;

    // Group items by (level, stream) so Loki gets properly labeled streams
    let mut groups: HashMap<(&str, &str), Vec<&HttpLogItem>> = HashMap::new();
    for item in items {
        groups
            .entry((item.level.as_str(), item.stream.as_str()))
            .or_default()
            .push(item);
    }

    let streams: Vec<Value> = groups
        .into_iter()
        .map(|((level, stream), entries)| {
            let mut labels = serde_json::Map::new();
            labels.insert("job".into(), Value::String(HTTP_JOB.clone()));
            labels.insert("level".into(), Value::String(level.to_string()));
            labels.insert("stream".into(), Value::String(stream.to_string()));
            for (k, v) in HTTP_LABELS.iter() {
                labels.insert(k.clone(), Value::String(v.clone()));
            }

            let values: Vec<Value> = entries
                .iter()
                .map(|e| json!([&e.timestamp_ns, &e.message]))
                .collect();

            json!({
                "stream": Value::Object(labels),
                "values": values,
            })
        })
        .collect();

    json!({ "streams": streams }).to_string()
}

/// Generic JSON array format: `[{"timestamp":"..","level":"..","message":".."}]`
fn format_json(items: &[HttpLogItem]) -> String {
    let entries: Vec<Value> = items
        .iter()
        .map(|item| {
            let mut obj = serde_json::Map::new();
            obj.insert("timestamp".into(), Value::String(item.timestamp_ns.clone()));
            obj.insert("level".into(), Value::String(item.level.clone()));
            obj.insert("stream".into(), Value::String(item.stream.clone()));
            obj.insert("message".into(), Value::String(item.message.clone()));
            obj.insert("job".into(), Value::String(HTTP_JOB.clone()));
            for (k, v) in HTTP_LABELS.iter() {
                obj.insert(k.clone(), Value::String(v.clone()));
            }
            Value::Object(obj)
        })
        .collect();

    Value::Array(entries).to_string()
}

/// Newline-delimited JSON (Elasticsearch / OpenSearch bulk-compatible).
fn format_ndjson(items: &[HttpLogItem]) -> String {
    let mut out = String::new();
    for item in items {
        let mut obj = serde_json::Map::new();
        obj.insert("timestamp".into(), Value::String(item.timestamp_ns.clone()));
        obj.insert("level".into(), Value::String(item.level.clone()));
        obj.insert("stream".into(), Value::String(item.stream.clone()));
        obj.insert("message".into(), Value::String(item.message.clone()));
        obj.insert("job".into(), Value::String(HTTP_JOB.clone()));
        for (k, v) in HTTP_LABELS.iter() {
            obj.insert(k.clone(), Value::String(v.clone()));
        }
        out.push_str(&Value::Object(obj).to_string());
        out.push('\n');
    }
    out
}
