# Changelog

All notable changes to `crypsol_logger` will be documented in this file.

## [0.3.5] - 2026-03-30

### Breaking Changes
- Default features are now `console` + `file` only.
  Projects using CloudWatch or HTTP backends must explicitly enable those features.

### Added
- Feature flags: `console`, `file`, `cloudwatch`, `http`.
- Stub functions for disabled backends so macros compile regardless of selected features.
- HTTP proxy via `logs::queue_http_log` to keep macro code independent of feature gates.

### Changed
- `aws-config`, `aws-sdk-cloudwatchlogs` are now optional (behind `cloudwatch`).
- `reqwest`, `base64` are now optional (behind `http`).
- `http_backend` module compiled only when `http` feature is enabled.
- All CloudWatch statics and functions gated behind `#[cfg(feature = "cloudwatch")]`.
- All file logging statics and functions gated behind `#[cfg(feature = "file")]`.
- HTTP-related statics and `is_log_to_http_enabled` gated behind `#[cfg(feature = "http")]`.

### Migration from 0.3.x
- If you only use console/file logging: just bump the version, no other changes needed.
- If you use CloudWatch: add `features = ["cloudwatch"]`.
- If you use Loki/Elasticsearch/HTTP: add `features = ["http"]`.
- If you use everything: add `features = ["console", "file", "cloudwatch", "http"]`.

## [0.3.4] - 2026-03-27

### Added
- Support for debug formatting (`=>?`) for structured log fields.

## [0.3.3] - 2026-03-27

### Added
- Basic Auth support for HTTP backend (`LOG_HTTP_AUTH_USER`, `LOG_HTTP_AUTH_TOKEN`).
- `LOG_GROUP` env var replaces `AWS_LOG_GROUP` (backward compatible).

## [0.3.2] - 2026-03-27

### Fixed
- Reverted `Value::from` to `format!()` for backward compatibility with `Display`-only types.

## [0.3.1] - 2026-03-27

### Fixed
- AccessDenied credential masking in error messages.
- Cleanup throttling for file backend.

### Changed
- Type-preserving structured fields.
- Clippy cleanup.

## [0.3.0] - 2026-03-27

### Added
- HTTP push backend (Loki, Elasticsearch, custom endpoints).
- File logging backend with automatic retention and cleanup.
- Console fallback when no backend is enabled.
- Structured JSON logging with `log!` key-value syntax.
- `log_custom!` macro for custom stream names.

## [0.2.2] - 2026-03-22

### Added
- Structured logging with key-value pairs.

## [0.2.1] - 2025-07-24

### Changed
- Enhanced logging, AWS throttling retry logic, version upgrades.

## [0.2.0] - 2025-06-30

### Added
- Local file logging and additional configuration controls.

## [0.1.0] - 2025-04-25

### Added
- Initial release with CloudWatch backend.
