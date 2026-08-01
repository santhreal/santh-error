use santh_error::{redact_secrets, SanthError};

#[test]
fn redact_embedded_jwt() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let input = format!("token={}", jwt);
    let out = redact_secrets(&input);
    assert!(!out.contains("eyJhbGci"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_github_token() {
    let input = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let out = redact_secrets(input);
    assert!(!out.contains("ghp_"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_github_fine_grained_pat() {
    let input = "github_pat_11ABCDEIJ0lmNoPQRstu_vwxyz12345678901234567890ABCDEFGHIJK";
    let out = redact_secrets(input);
    assert!(!out.contains("github_pat_"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_password_field() {
    let cases = [
        ("password=hunter2", "hunter2"),
        ("passwd:hunter2", "hunter2"),
        ("Password = hunter2", "hunter2"),
        ("PASSWORD:hunter2", "hunter2"),
        ("api_key=secret123", "secret123"),
        ("api-key:secret123", "secret123"),
        ("token=abcd", "abcd"),
        ("secret=shh", "shh"),
    ];

    for (input, secret) in &cases {
        let out = redact_secrets(input);
        assert!(!out.contains(secret), "failed to redact secret in: {input}");
        assert!(out.contains("[REDACTED]"), "missing [REDACTED] in: {input}");
    }
}

#[test]
fn redact_bearer_token() {
    let input = "Authorization: Bearer abc123def456";
    let out = redact_secrets(input);
    assert!(!out.contains("abc123def456"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_openai_key() {
    let input = "sk-abcdefghijklmnopqrstuvwxyz123456";
    let out = redact_secrets(input);
    assert!(!out.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_openai_project_key() {
    // Project keys carry `sk-proj-` with an internal hyphen that a pure
    // `[a-zA-Z0-9]` body would refuse to match.
    let input = "OPENAI_API_KEY=sk-proj-abcDEF0123456789ghijKLMN";
    let out = redact_secrets(input);
    assert!(!out.contains("sk-proj-abcDEF0123456789ghijKLMN"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_bearer_token_case_insensitive() {
    // Lowercase/uppercase scheme spellings must still redact the token.
    for input in ["authorization: bearer abc123def456", "BEARER abc123def456"] {
        let out = redact_secrets(input);
        assert!(!out.contains("abc123def456"), "leaked from: {input}");
        assert!(out.contains("[REDACTED]"));
    }
}

#[test]
fn redact_aws_session_key() {
    // STS temporary/session credentials use the ASIA prefix, not AKIA.
    let input = "aws_access_key_id = ASIAJKLMNOPQRSTUVWXY";
    let out = redact_secrets(input);
    assert!(!out.contains("ASIAJKLMNOPQRSTUVWXY"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_private_key() {
    let key = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----";
    let out = redact_secrets(key);
    assert!(!out.contains("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn redact_rsa_private_key() {
    let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
    let out = redact_secrets(key);
    assert!(!out.contains("MIIEpAIBAAKCAQEA"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn unicode_in_context_values() {
    let err = SanthError::new("TEST-U001", "Unicode test")
        .with_context("emoji", "🚀🔥💀")
        .with_context("chinese", "这是一个测试")
        .with_context("arabic", "هذا اختبار")
        .with_context("zalgo", "T̷͓̖͈̲̩̗h̴͍͙͚͕͓i̶͈s̷̡̛̞")
        .fix("Fix: No action needed, this is a test.")
        .build();

    let msg = err.actionable_message();
    assert!(msg.contains("🚀🔥💀"));
    assert!(msg.contains("这是一个测试"));
    assert!(msg.contains("هذا اختبار"));
    assert!(msg.contains("T̷͓̖͈̲̩̗h̴͍͙͚͕͓i̶͈s̷̡̛̞"));
    assert!(msg.contains("Fix: "));
}

#[test]
fn very_long_message_redaction() {
    let secret = "sk-".to_string() + &"a".repeat(100_000);
    let input = format!("prefix {} suffix", secret);
    let out = redact_secrets(&input);
    assert!(!out.contains(&secret));
    assert!(out.contains("[REDACTED]"));
    assert!(out.starts_with("prefix "));
    assert!(out.ends_with(" suffix"));
}

#[test]
fn multiple_secrets_in_one_string() {
    let input = "password=foo api_key=bar token=baz secret=qux";
    let out = redact_secrets(input);
    assert!(!out.contains("foo"));
    assert!(!out.contains("bar"));
    assert!(!out.contains("baz"));
    assert!(!out.contains("qux"));
}

#[test]
fn secret_in_context_gets_redacted_in_actionable_message() {
    let err = SanthError::new("TEST-SEC-01", "Request failed")
        .with_context("auth", "Bearer supersecrettoken12345")
        .fix("Fix: Retry the request with a valid token.")
        .build();

    let msg = err.actionable_message();
    assert!(!msg.contains("supersecrettoken12345"));
    assert!(msg.contains("[REDACTED]"));
}

#[test]
fn aws_key_in_title_gets_redacted() {
    let err = SanthError::new("TEST-SEC-02", "Key AKIAIOSFODNN7EXAMPLE is invalid")
        .fix("Fix: Rotate the AWS access key.")
        .build();

    let msg = err.actionable_message();
    assert!(!msg.contains("AKIAIOSFODNN7EXAMPLE"));
    assert!(msg.contains("[REDACTED]"));
}

#[test]
fn redact_quoted_password_with_spaces() {
    // A bare `\S+` value stops at the first space, leaking the remainder of a
    // quoted secret. The shared quoted-or-unquoted value fragment must redact
    // the whole value.
    let cases = [
        (r#"password="my secret pass""#, "my secret pass"),
        (r#"password = "hunter two three""#, "hunter two three"),
        ("password='single quoted secret'", "single quoted secret"),
        (r#"api_key="key with spaces""#, "key with spaces"),
        (r#"token="a b c d""#, "a b c d"),
        (r#"secret="sh h""#, "sh h"),
    ];
    for (input, secret) in &cases {
        let out = redact_secrets(input);
        assert!(!out.contains(secret), "leaked quoted secret in {input:?} -> {out:?}");
        assert!(out.contains("[REDACTED]"), "missing [REDACTED] in {input:?} -> {out:?}");
    }
}

#[test]
fn cyclic_source_chain_terminates_with_truncation_marker() {
    // Regression lock: `compose_message` walked `source()` links with no
    // bound. A custom error type whose `source()` returns itself made
    // `actionable_message` loop forever while the message grew without limit
    // (hang plus memory exhaustion). The walk is capped and the truncation is
    // announced, so diagnostic loss is visible, never silent.
    use std::fmt;

    #[derive(Debug)]
    struct Cycle;
    impl fmt::Display for Cycle {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("cyclic source")
        }
    }
    impl std::error::Error for Cycle {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    let err = SanthError::new("TEST-E001", "cycle probe")
        .fix("Fix: nothing to fix in the test")
        .with_source(Cycle)
        .build();
    let msg = err.actionable_message();
    assert!(
        msg.contains("source chain truncated after 64 links"),
        "a cyclic source chain must be cut with a visible marker: {msg}"
    );
    assert!(
        msg.len() < 16 * 1024,
        "the message must stay bounded for a cyclic chain, got {} bytes",
        msg.len()
    );
}

#[test]
fn redact_bearer_token_with_dots() {
    // Regression lock: the bearer pattern only accepted URL-safe base64, so a
    // dotted OAuth access token after `Bearer ` leaked in full. Dotted bodies
    // must redact like any other bearer token.
    let out = redact_secrets("Authorization: Bearer abc.def.ghi-jkl_mno");
    assert!(
        !out.contains("abc.def.ghi"),
        "dotted bearer token must be redacted: {out}"
    );
    assert!(out.contains("[REDACTED]"));
}
