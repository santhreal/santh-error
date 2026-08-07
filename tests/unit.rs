use santh_error::{redact_secrets, ErrorLocation, SanthError};

#[test]
fn builder_round_trip() {
    let err = SanthError::new("TEST-E001", "Something broke")
        .with_context("user", "alice")
        .with_location(
            ErrorLocation::new("/etc/config.toml")
                .with_line(42)
                .with_column(7),
        )
        .fix("Fix: Restart the service and check the logs.")
        .build();

    assert_eq!(err.code(), "TEST-E001");
    assert_eq!(err.title(), "Something broke");
    assert_eq!(
        err.fix_hint(),
        "Fix: Restart the service and check the logs."
    );
}

#[test]
fn display_includes_fix_and_context() {
    let err = SanthError::new("TEST-E002", "Failed to parse config")
        .with_context("path", "/etc/app.toml")
        .fix("Fix: Validate the TOML syntax using `toml-test`.")
        .build();

    let msg = format!("{err}");
    assert!(msg.contains("Failed to parse config"));
    assert!(msg.contains("Fix: Validate the TOML syntax"));
    assert!(msg.contains("path: /etc/app.toml"));
}

#[test]
fn source_chain_walking() {
    let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
    let outer = SanthError::new("TEST-E003", "Outer error")
        .with_source(inner)
        .fix("Fix: Check the underlying cause.")
        .build();

    assert!(std::error::Error::source(&outer).is_some());
    let src = std::error::Error::source(&outer).unwrap();
    assert!(src.to_string().contains("file gone"));
}

#[test]
fn display_includes_source_chain() {
    let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
    let outer = SanthError::new("TEST-E003", "Outer error")
        .with_source(inner)
        .fix("Fix: Check the underlying cause.")
        .build();

    let msg = format!("{outer}");
    assert!(
        msg.contains("Caused by:"),
        "Display should include source chain"
    );
    assert!(
        msg.contains("file gone"),
        "Display should include source message"
    );
}

#[test]
fn redact_aws_key() {
    let input =
        "Access key is AKIAIOSFODNN7EXAMPLE and secret is wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let out = redact_secrets(input);
    assert!(!out.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_preserves_non_secret_text() {
    let input = "Hello world, no secrets here.";
    assert_eq!(redact_secrets(input), input);
}

#[test]
fn from_io_error_discriminates_not_found() {
    let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let err: SanthError = io.into();
    assert_eq!(err.code(), "SANTH-IO-NOTFOUND");
    assert!(err.actionable_message().contains("Fix: "));
    assert!(err.actionable_message().contains("missing"));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn from_io_error_discriminates_permission_denied() {
    let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
    let err: SanthError = io.into();
    assert_eq!(err.code(), "SANTH-IO-PERM");
    assert!(err.actionable_message().contains("Fix: "));
    assert!(std::error::Error::source(&err).is_some());
}

#[test]
fn from_utf8_error_sets_default_fix() {
    let bytes = vec![0x80, 0x81];
    let utf8_err = String::from_utf8(bytes).unwrap_err();
    let err: SanthError = utf8_err.into();
    assert_eq!(err.code(), "SANTH-UTF8-01");
    assert!(err.actionable_message().contains("Fix: "));
}

#[test]
fn from_fmt_error_sets_default_fix() {
    let fmt_err = std::fmt::Error;
    let err: SanthError = fmt_err.into();
    assert_eq!(err.code(), "SANTH-FMT-01");
    assert!(err.actionable_message().contains("Fix: "));
}

#[test]
fn from_regex_error_sets_default_fix() {
    // Intentionally invalid pattern (unclosed character class). `black_box`
    // keeps the literal out of clippy's static `invalid_regex` lint while
    // still exercising the runtime `From<regex::Error>` conversion path.
    let regex_err = regex::Regex::new(std::hint::black_box("[")).unwrap_err();
    let err: SanthError = regex_err.into();
    assert_eq!(err.code(), "SANTH-REGEX-01");
    assert!(err.actionable_message().contains("Fix: "));
}

#[test]
fn location_rendered_in_actionable_message() {
    let err = SanthError::new("TEST-E004", "Bad config")
        .with_location(ErrorLocation::new("config.yaml").with_line(10))
        .fix("Fix: Fix the yaml.")
        .build();

    let msg = err.actionable_message();
    assert!(msg.contains("Location: config.yaml:10:?"));
}

#[test]
fn partial_eq_ignores_source() {
    let a = SanthError::new("TEST-EQ", "Equality test")
        .with_context("key", "val")
        .fix("Fix: nothing.")
        .build();

    let b = SanthError::new("TEST-EQ", "Equality test")
        .with_context("key", "val")
        .with_source(std::io::Error::other("boom"))
        .fix("Fix: nothing.")
        .build();

    assert_eq!(a, b);
}

#[test]
fn partial_eq_different_code_is_not_equal() {
    let a = SanthError::new("TEST-A", "Same title")
        .fix("Fix: nothing.")
        .build();
    let b = SanthError::new("TEST-B", "Same title")
        .fix("Fix: nothing.")
        .build();
    assert_ne!(a, b);
}

#[test]
fn dynamic_context_key_works() {
    let key: String = "dynamic".to_string();
    let err = SanthError::new("TEST-DYN", "Dynamic key test")
        .with_context(key, "value")
        .fix("Fix: nothing.")
        .build();

    let msg = err.actionable_message();
    assert!(msg.contains("dynamic: value"));
}
#[test]
fn multiline_and_empty_source_error_formatting() {
    #[derive(Debug)]
    struct MultilineSource;
    impl std::fmt::Display for MultilineSource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "first line\nsecond line")
        }
    }
    impl std::error::Error for MultilineSource {}

    let err = SanthError::new("TEST-M001", "Multiline source error")
        .with_source(MultilineSource)
        .fix("Fix: Inspect the multiline source cause.")
        .build();

    let msg = err.actionable_message();
    assert!(msg.contains("  - first line\n    second line"));

    #[derive(Debug)]
    struct EmptySource;
    impl std::fmt::Display for EmptySource {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "")
        }
    }
    impl std::error::Error for EmptySource {}

    let err_empty = SanthError::new("TEST-M002", "Empty source error")
        .with_source(EmptySource)
        .fix("Fix: Handle empty source cause.")
        .build();

    let msg_empty = err_empty.actionable_message();
    assert!(msg_empty.contains("  - (empty error message)"));
}
