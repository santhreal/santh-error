# santh-error

[![status: beta](https://img.shields.io/badge/status-beta-orange.svg)](https://santh.dev)

> **Internal Santh tooling.** This crate is shared infrastructure for Santh
> crates, not a public library. It is not published to crates.io and its API
> carries no stability guarantee for external users. If you are building
> something outside Santh, use `thiserror`, `anyhow`, or `miette` instead.

## What it does

Shared error primitives for Santh crates. Every error carries a stable,
machine-readable code, a human title, and an explicit `Fix:` hint, so a failure
tells the operator what to do instead of only what went wrong. A
`SanthErrorContract` trait lets any domain error enum join the same contract
without folding its variants into a central type, and every rendered message
passes through built-in secret redaction.

## Quick start

```rust
use santh_error::SanthError;

let err = SanthError::new("CFG-E001")
    .title("config file not found")
    .fix("Fix: create config.toml or pass --config")
    .build();

println!("{}", err.actionable_message());
```

## When to use / When not

Use it for any Santh crate that surfaces errors to an operator, or whenever you
want a stable error code plus an enforced fix hint.

Do not reach for it as a general application-error library outside Santh; it
encodes Santh-specific conventions (the `Fix:` rule, fleet error codes, and
automatic redaction) that a generic project does not need.

## Compared to alternatives

`thiserror` and `anyhow` give ergonomic error types and context chaining but say
nothing about *actionability*: nothing forces a fix hint, a stable code, or
secret redaction. `miette` adds rich diagnostics and source spans, which is more
than a CLI needs and carries a heavier dependency tree. `santh-error` is small
and opinionated: it guarantees the three fields every Santh error must answer
and redacts secrets by default, while still interoperating with `thiserror`
enums through the `SanthErrorContract` trait.

## How it fits in Santh

`santh-error` is the base of the `libs/general` layer. It depends only on
`regex` and is depended on by `santh-tracing` (which reuses its redactor) and by
the domain crates that implement `SanthErrorContract`. It must not depend on any
higher layer.

## Contributing

Add new secret patterns to `redact.rs` with a matching case in
`tests/adversarial.rs`, keep every public error path covered by
`tests/contract.rs`, and uphold the one rule: every error has a `Fix:` hint.

## License

Licensed under either MIT or Apache-2.0.
