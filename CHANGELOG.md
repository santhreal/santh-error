# Changelog

## [0.2.3] - 2026-08-07

### Security
- Redact `SanthError` fields in `fmt::Debug` output to prevent credential leakage via `{:?}` debug logging.
- Expanded secret redaction to cover HTTP `Basic` authorization headers, GitLab PATs (`glpat-`), Slack `xapp-` tokens, `credential(s)=` KV pairs, and PGP/encrypted PEM private key blocks.

### Fixed
- `compose_message` now normalises `fix_hint` values from custom `SanthErrorContract` implementations to guarantee the `"Fix: "` prefix invariant fleet-wide.
- Multiline source error messages in `Caused by:` chains are indented for clean bullet alignment, and empty source error messages are rendered as `(empty error message)` instead of blank lines.

## [0.2.2] - 2026-08-07

### Security
- Expanded secret redaction (Slack/GCP/Stripe/compound KV).

### Changed
- Crate authors set to Santh noreply.


All notable changes to this crate are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and semantic versioning.

## 0.2.1

### Fixed

- `actionable_message` now caps the `source()` chain walk at 64 links. A
  custom error type that returns itself (or a pathologically long chain) from
  `source()` previously made the renderer loop forever while the message grew
  without bound. Past the cap the chain is cut with a visible
  `(source chain truncated after 64 links)` marker.

### Security

- `redact_secrets` now redacts dotted bearer tokens (`Bearer abc.def.ghi`).
  The pattern previously accepted only URL-safe base64, so OAuth access tokens
  whose bodies contain dots leaked in full.
- `redact_secrets` now redacts Slack API tokens (`xoxb-`, `xoxp-`, `xapp-`, etc.),
  GCP API keys (`AIzaSy...`), Stripe API keys (`sk_live_...`, `rk_live_...`), and
  compound KV secret pairs (`client_secret=`, `secret_key=`, `access_token=`,
  `passphrase=`, `signing_key=`).

## 0.2.0

### Added

- `SanthErrorContract` trait: a domain error enum joins the fleet-wide error
  contract (`error_code`, `fix_hint`, and a shared `actionable_message`
  renderer) by implementing two methods, without folding its variants into
  `SanthError`.
- `impl SanthErrorContract for SanthError`, so the canonical type and every
  domain error render through the same formatter.
- `redact_secrets` now also masks credentials embedded in URL userinfo
  (`scheme://user:pass@host` becomes `scheme://***@host`), preserving the scheme
  and host. Redaction is documented and property-tested as idempotent.

### Changed

- `actionable_message` now delegates to a shared `compose_message` helper, so
  the inherent method and the trait default produce identical output.
- `SanthErrorBuilder::build` no longer calls `expect`; the `HasFix` typestate
  already guarantees a fix hint, and an empty hint is normalised to the
  `"Fix: "` prefix.

## 0.1.0

- Initial release: `SanthError`, the typestate `SanthErrorBuilder`,
  `ErrorLocation`, and `redact_secrets`.
