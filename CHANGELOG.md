# Changelog

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
