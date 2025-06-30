# 🚀 crypsol_logger

Structured and production-grade logger for your applications, with seamless AWS CloudWatch support and local fallback logging.

---

## 🔥 Features

- ✅ Structured JSON logging
- ✅ Batch and compress logs before sending
- ✅ AWS CloudWatch integration
- ✅ Automatic fallback to local stdout logging
- ✅ Thread-safe, high-performance design
- ✅ Minimal configuration required

---

## 📦 Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
crypsol_logger = "0.1.0"
```
The `Level` enum is re-exported, so there's no need to add the `log` crate separately.

---

## 🛠 Setup & Usage

You can use the log! macro to generate logs. This macro will automatically check the environment variable and accordingly send logs to CloudWatch or print them to the console.

```rust
log!(Level::Info, "This is an info message");
log!(Level::Error, "This is an error message");
log!(Level::Debug, "Debugging information");
```

To log in a custom stream (other than info, error and debug) you can use log_custom macro

```rust
log_custom!(Level::Info,"Custom Stream Name", "This is the message and variable {variable}");
```

✅ That's it! Logs are automatically captured and either sent to AWS CloudWatch or printed locally.

---

## 🧪 Environment Variables

| Variable | Description |
|----------|-------------|
| `CLOUDWATCH_AWS_ACCESS_KEY` | Your AWS Access Key |
| `CLOUDWATCH_AWS_SECRET_KEY` | Your AWS Secret Key |
| `CLOUDWATCH_AWS_REGION` | AWS Region (default: `us-east-1`) |
| `AWS_LOG_GROUP` | CloudWatch log group name |
| `LOG_TO_CLOUDWATCH` | Set this to false if you want to disable logging to CloudWatch (default is false) |
| `LOG_TO_FILE` | Set this to true to write logs to local files |
| `LOG_FILE_DIR` | Directory path for local logs (default: `logs`) |
| `LOG_BATCH_SIZE` | Max logs per batch (default: 10) |
| `BATCH_TIMEOUT` | Max time to wait for putting a log event |
| `LOG_RETENTION_DAYS` | Days to keep log files on disk (default: `30`) |
| `LOG_RETENTION_SIZE_MB` | Max total size of logs before old files are deleted (default: `512`) |
| `LOG_DELETE_BATCH_MB` | Amount of oldest logs removed when the size limit is hit (default: `100`) |
| `LOG_SHOW_LOCATION` | Include file path and line number in logs (default: `false`) |

---

## 📜 License

MIT © 2025 [Crypsol](https://crypsol.tech/)

---

## 🧠 Also Available in Python!
A **Python version** of this logger, which is also easily integratable with FastAPI, Flask, and other WSGI/ASGI frameworks:  
🔗 [cloudwatchpy — Python Logger for AWS CloudWatch](https://github.com/Irfan-Ahmad-byte/cloudwatchpy)