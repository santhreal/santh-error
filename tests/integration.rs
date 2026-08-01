//! Integration: a fully-populated `SanthError` renders one actionable message
//! that joins title, fix, context, and location, with a secret in the source
//! chain redacted - exercising the builder, `compose_message`, and `redact`
//! together rather than any one in isolation.

use santh_error::{ErrorLocation, SanthError};

#[test]
fn full_error_renders_actionable_message_with_redaction() {
    let source = std::io::Error::other(
        "upstream failed: token=ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD",
    );
    let err = SanthError::new("CFG-E007", "failed to load config")
        .with_context("path", "/etc/app/config.toml")
        .with_location(ErrorLocation::new("/etc/app/config.toml").with_line(12))
        .with_source(source)
        .fix("Fix: check the path and permissions")
        .build();

    let msg = err.actionable_message();

    assert!(
        msg.contains("failed to load config"),
        "title present: {msg}"
    );
    assert!(
        msg.contains("Fix: check the path and permissions"),
        "fix present: {msg}"
    );
    assert!(
        msg.contains("/etc/app/config.toml"),
        "location/context present: {msg}"
    );
    assert!(
        !msg.contains("ghp_0123456789"),
        "raw secret must be redacted: {msg}"
    );
    assert!(
        msg.contains("[REDACTED]"),
        "redaction marker present: {msg}"
    );
}
