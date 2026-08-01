use proptest::prelude::*;
use santh_error::{redact_secrets, SanthError};

proptest! {
    // The CLAUDE.md / STANDARD type-6 contract: 10 000 cases per invariant.
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    #[test]
    fn actionable_message_always_contains_fix(
        title in "[a-zA-Z0-9 _-]{1,100}",
        fix_body in "[a-zA-Z0-9 ,.;:!?_-]{1,200}",
    ) {
        let fix = format!("Fix: {fix_body}");
        let err = SanthError::new("PROP-E001", title)
            .fix(&fix)
            .build();

        let msg = err.actionable_message();
        prop_assert!(
            msg.contains("Fix: "),
            "actionable_message missing 'Fix: ': {msg}"
        );
    }

    #[test]
    fn actionable_message_with_context_always_contains_fix(
        title in "[a-zA-Z0-9 _-]{1,100}",
        fix_body in "[a-zA-Z0-9 ,.;:!?_-]{1,200}",
        ctx_value in r"[a-zA-Z0-9 _\-=@.]{0,500}",
    ) {
        let fix = format!("Fix: {fix_body}");
        let err = SanthError::new("PROP-E002", title)
            .with_context("key", ctx_value)
            .fix(&fix)
            .build();

        let msg = err.actionable_message();
        prop_assert!(
            msg.contains("Fix: "),
            "actionable_message missing 'Fix: '"
        );
    }

    #[test]
    fn actionable_message_with_source_always_contains_fix(
        title in "[a-zA-Z0-9 _-]{1,100}",
        fix_body in "[a-zA-Z0-9 ,.;:!?_-]{1,200}",
    ) {
        let fix = format!("Fix: {fix_body}");
        let inner = std::io::Error::other("boom");
        let err = SanthError::new("PROP-E003", title)
            .with_source(inner)
            .fix(&fix)
            .build();

        let msg = err.actionable_message();
        prop_assert!(
            msg.contains("Fix: "),
            "actionable_message missing 'Fix: '"
        );
        prop_assert!(
            msg.contains("Caused by:"),
            "actionable_message should include source chain"
        );
    }

    // ---- redact_secrets invariants (the canonical, security-critical matcher) ----

    /// Redacting an already-redacted string changes nothing: a second pass must
    /// not find new matches in the `[REDACTED]` markers the first pass left.
    /// A counterexample would mean redaction does not converge.
    #[test]
    fn redaction_is_idempotent(input in "(?s).{0,400}") {
        let once = redact_secrets(&input);
        let twice = redact_secrets(&once);
        prop_assert_eq!(once, twice, "redaction is not idempotent for input: {:?}", input);
    }

    /// Redaction never panics and always terminates on arbitrary Unicode input.
    /// (The `regex` crate is linear-time, so this also rules out ReDoS.)
    #[test]
    fn redaction_never_panics_on_arbitrary_input(input in "(?s).{0,400}") {
        let _ = redact_secrets(&input);
    }

    /// An embedded AWS access key never survives redaction verbatim, regardless
    /// of surrounding (secret-free) text.
    #[test]
    fn aws_key_is_always_redacted(
        prefix in "[a-z ]{0,50}",
        key in "AKIA[0-9A-Z]{16}",
        suffix in "[a-z ]{0,50}",
    ) {
        let input = format!("{prefix}{key}{suffix}");
        let out = redact_secrets(&input);
        prop_assert!(!out.contains(&*key), "raw AWS key survived redaction: {out}");
        prop_assert!(out.contains("[REDACTED]"), "no redaction marker emitted: {out}");
    }

    /// A GitHub personal access token never survives redaction verbatim.
    #[test]
    fn github_pat_is_always_redacted(token in "ghp_[A-Za-z0-9]{36,40}") {
        let input = format!("authorization: token {token}");
        let out = redact_secrets(&input);
        prop_assert!(!out.contains(&*token), "raw GitHub PAT survived redaction: {out}");
        prop_assert!(out.contains("[REDACTED]"), "no redaction marker emitted: {out}");
    }

    /// URL userinfo credentials are masked, while the scheme and host (which
    /// are not secret) survive. `user`/`pass` use pattern-free alphabets so the
    /// only redaction under test is the URL-userinfo masking itself.
    #[test]
    fn url_userinfo_credentials_are_masked(
        user in "[a-z]{1,20}",
        pass in "[a-z0-9]{1,30}",
        host in "[a-z]{1,20}\\.[a-z]{2,4}",
    ) {
        let input = format!("https://{user}:{pass}@{host}/path");
        let out = redact_secrets(&input);
        prop_assert!(!out.contains(&format!("{user}:{pass}")), "credentials survived: {out}");
        prop_assert!(out.contains("https://***@"), "userinfo not masked: {out}");
        prop_assert!(out.contains(&*host), "host should be preserved: {out}");
    }

    /// Text containing no secret pattern passes through completely unchanged:
    /// redaction must not corrupt benign output. Lowercase letters and spaces
    /// match none of the secret patterns (all of which need uppercase prefixes,
    /// `=`/`:` separators, or `_`/`-` characters).
    #[test]
    fn pattern_free_text_is_unchanged(input in "[a-z ]{0,300}") {
        prop_assert_eq!(redact_secrets(&input), input);
    }
}
