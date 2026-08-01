//! External contract: the `SanthErrorContract` trait. A domain error enum
//! joins the contract by implementing two methods - its variants stay local
//! (zero functionality loss, no API duplicated upward) - and renders through
//! the same formatter as the canonical `SanthError`.

use std::borrow::Cow;
use std::fmt;

use santh_error::{ErrorLocation, SanthError, SanthErrorContract};

/// A domain error enum that keeps its own variants and implements the
/// contract. This is the canonical fleet-wide adoption shape: the crate owns
/// its error vocabulary; `santh-error` owns the contract.
#[derive(Debug)]
enum DomainError {
    ShapeMismatch { want: usize, got: usize },
    NotFound(String),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DomainError::ShapeMismatch { want, got } => {
                write!(f, "tensor shape mismatch: wanted {want}, got {got}")
            }
            DomainError::NotFound(id) => write!(f, "node {id} not found"),
        }
    }
}

impl std::error::Error for DomainError {}

impl SanthErrorContract for DomainError {
    fn error_code(&self) -> &'static str {
        match self {
            DomainError::ShapeMismatch { .. } => "DOMAIN-E001",
            DomainError::NotFound(_) => "DOMAIN-E002",
        }
    }

    fn fix_hint(&self) -> Cow<'_, str> {
        match self {
            DomainError::ShapeMismatch { .. } => {
                Cow::Borrowed("Fix: Reshape the input tensor to match the expected dimensions.")
            }
            DomainError::NotFound(_) => {
                Cow::Borrowed("Fix: Verify the node id exists in the graph before referencing it.")
            }
        }
    }
}

#[test]
fn domain_error_renders_code_title_and_fix_via_contract() {
    let err = DomainError::ShapeMismatch { want: 4, got: 3 };
    assert_eq!(err.error_code(), "DOMAIN-E001");
    let msg = err.actionable_message();
    assert!(
        msg.contains("tensor shape mismatch: wanted 4, got 3"),
        "title must come from Display: {msg}"
    );
    assert!(
        msg.contains("Fix: Reshape the input tensor"),
        "fix hint must be present: {msg}"
    );
}

#[test]
fn domain_error_defaults_empty_context_and_no_location() {
    let err = DomainError::NotFound("n7".to_string());
    assert!(err.context().is_empty());
    assert!(err.location().is_none());
    assert!(err.actionable_message().contains("node n7 not found"));
}

#[test]
fn trait_and_inherent_formatters_do_not_diverge() {
    let err = SanthError::new("TEST-CONTRACT", "Boom")
        .with_context("k", "v")
        .with_location(ErrorLocation::new("f.toml").with_line(3))
        .fix("Fix: do the thing.")
        .build();

    let via_trait = SanthErrorContract::actionable_message(&err);
    let via_inherent = err.actionable_message();
    assert_eq!(
        via_trait, via_inherent,
        "the trait default and the inherent formatter must produce identical output"
    );
}

#[test]
fn contract_message_redacts_secret_in_context_value() {
    let err = SanthError::new("TEST-RED", "Auth failed")
        .with_context("authorization", "Bearer sk-abcdefghij0123456789XYZ")
        .fix("Fix: rotate the token and retry.")
        .build();

    let msg = SanthErrorContract::actionable_message(&err);
    assert!(
        !msg.contains("sk-abcdefghij0123456789XYZ"),
        "a secret in context must be redacted from the contract message: {msg}"
    );
    assert!(msg.contains("[REDACTED]"));
}

#[test]
fn contract_error_code_is_stable_per_variant() {
    assert_eq!(
        DomainError::NotFound("x".to_string()).error_code(),
        "DOMAIN-E002"
    );
    assert_eq!(
        DomainError::ShapeMismatch { want: 1, got: 2 }.error_code(),
        "DOMAIN-E001"
    );
}

/// ONE-PLACE lock: the `with_context` / `with_source` / `with_location`
/// mutators are generated once by `impl_diagnostic_mutators!` and shared by
/// both `SanthErrorBuilder` (pre-build) and `SanthError` (post-build). Enrich
/// one error entirely through the builder and an equivalent error entirely
/// through the built value; the rendered messages must be byte-identical. If
/// either impl ever re-forks a divergent mutator body, these bytes drift and
/// this test fails.
#[test]
fn builder_and_built_mutators_render_identically() {
    #[derive(Debug)]
    struct Cause;
    impl fmt::Display for Cause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "underlying io failure")
        }
    }
    impl std::error::Error for Cause {}

    // Path A: all enrichment on the builder, before build.
    let via_builder = SanthError::new("PARITY-E001", "Parity check")
        .with_context("key", "value")
        .with_source(Cause)
        .with_location(ErrorLocation::new("src/lib.rs").with_line(42).with_column(7))
        .fix("Fix: nothing, this is a parity probe.")
        .build();

    // Path B: build a bare error, then apply the identical enrichment on the
    // built `SanthError` via its own (macro-shared) mutators.
    let via_built = SanthError::new("PARITY-E001", "Parity check")
        .fix("Fix: nothing, this is a parity probe.")
        .build()
        .with_context("key", "value")
        .with_source(Cause)
        .with_location(ErrorLocation::new("src/lib.rs").with_line(42).with_column(7));

    assert_eq!(
        via_builder.actionable_message(),
        via_built.actionable_message(),
        "builder-side and built-side diagnostic mutators must be the same single implementation"
    );
    // Assert concrete content, not just equality, so a shared-but-broken impl
    // (e.g. both silently dropping context) can't pass by both being empty.
    let msg = via_built.actionable_message();
    assert!(msg.contains("Context:"), "context must render: {msg}");
    assert!(msg.contains("  key: value"), "context entry must render: {msg}");
    assert!(msg.contains("Location: src/lib.rs:42:7"), "location must render: {msg}");
    assert!(msg.contains("Caused by:"), "source chain must render: {msg}");
    assert!(msg.contains("underlying io failure"), "source msg must render: {msg}");
}
