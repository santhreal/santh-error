use regex::Regex;
use std::borrow::Cow;
use std::sync::LazyLock;

// Every `source` below is a hardcoded literal validated by the redaction
// tests (each pattern is exercised by `tests/adversarial.rs`), so a compile
// failure here can only mean a literal in *this file* was edited to be
// invalid - a build-time programming error. We deliberately fail loud rather
// than skip the pattern: silently dropping a rule would let the matching
// secret class leak, which is strictly worse than a panic for a redaction
// primitive. `clippy::panic` is allowed for exactly this fail-loud-on-static-
// misconfiguration case.
/// Value fragment for `key = value` secret patterns: a double-quoted string, a
/// single-quoted string, or an unquoted whitespace-delimited token. Defined
/// once so every KV rule redacts quoted/spaced secrets identically (a bare
/// `\S+` stops at the first space and leaks the rest of a quoted secret).
const KV_VALUE: &str = r#"("[^"]*"|'[^']*'|\S+)"#;

#[allow(clippy::panic)]
fn compile(tag: &'static str, source: &str) -> Regex {
    Regex::new(source).unwrap_or_else(|e| {
        panic!(
            "santh-error::redact: secret pattern `{tag}` failed to compile: {e}. \
             Fix: correct the regex source in `redact.rs` for `{tag}`."
        )
    })
}

static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // Covers both long-term (AKIA) and temporary/STS session (ASIA) access keys.
        compile("aws_access_key", r"A[KS]IA[0-9A-Z]{16}"),
        compile("github_pat_classic", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        compile("github_pat_fine", r"github_pat_[A-Za-z0-9_]{22,}"),
        compile("gitlab_pat", r"glpat-[A-Za-z0-9_-]{20,}"),
        compile(
            "jwt",
            r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        ),
        // Bearer or Basic authorization tokens/credentials.
        compile("auth_header", r"(?i)(?:Bearer|Basic)\s+[A-Za-z0-9_./+-]+=*"),
        compile("password_kv", &format!(r"(?i)(?:pass(?:word|wd|code)|passphrase)\s*[=:]\s*{KV_VALUE}")),
        compile("api_key_kv", &format!(r"(?i)(?:api|secret|access|private|master|signing|encryption|auth|session)[_-]?key\s*[=:]\s*{KV_VALUE}")),
        compile("token_kv", &format!(r"(?i)(?:[a-z0-9_-]+[_-])?token\s*[=:]\s*{KV_VALUE}")),
        compile("secret_kv", &format!(r"(?i)(?:[a-z0-9_-]+[_-])?secret(?:[_-][a-z0-9_-]+)?\s*[=:]\s*{KV_VALUE}")),
        compile("credential_kv", &format!(r"(?i)credentials?\s*[=:]\s*{KV_VALUE}")),
        compile("slack_token", r"(?:xox[baprs]|xapp)-[a-zA-Z0-9_-]{10,}"),
        compile("gcp_api_key", r"AIzaSy[A-Za-z0-9_-]{33}"),
        compile("stripe_api_key", r"(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}"),
        // Body allows '-' and '_' so project keys (sk-proj-...) and other
        // hyphen/underscore-bearing key shapes are redacted, not just classic
        // sk- keys whose body is pure alphanumeric.
        compile("openai_api_key", r"sk-[a-zA-Z0-9_-]{20,}"),
        compile(
            "pem_private_key",
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----",
        ),
    ]
});

/// URL userinfo carrying credentials: `scheme://user:pass@host`. Rewritten to
/// `scheme://***@host`, preserving the scheme and host (not secret) while
/// stripping the embedded credentials. Kept separate from [`SECRET_PATTERNS`]
/// because it rewrites only the userinfo span instead of replacing the whole
/// match with `[REDACTED]`.
static URL_USERINFO: LazyLock<Regex> =
    LazyLock::new(|| compile("url_userinfo", r"://[^/@\s]*:[^/@\s]*@"));

/// Strip known-sensitive patterns from the input string.
///
/// Replaces known secret patterns (API keys, tokens, JWTs, `password=` pairs,
/// PEM private keys) with `[REDACTED]`, and masks credentials embedded in URL
/// userinfo (`scheme://user:pass@host` becomes `scheme://***@host`). This is a
/// safe-default measure to ensure secrets do not leak into logs, error
/// messages, or temp files. The operation is idempotent.
///
/// # Examples
///
/// ```
/// use santh_error::redact_secrets;
///
/// let raw = "password=hunter2";
/// let safe = redact_secrets(raw);
/// assert!(!safe.contains("hunter2"));
/// assert!(safe.contains("[REDACTED]"));
///
/// // URL credentials are masked while the scheme and host survive.
/// let url = redact_secrets("https://admin:s3cret@example.com/path");
/// assert!(!url.contains("s3cret"));
/// assert!(url.contains("https://***@example.com/path"));
/// ```
pub fn redact_secrets(input: &str) -> String {
    let mut output = input.to_string();
    for pattern in SECRET_PATTERNS.iter() {
        // `replace_all` returns `Cow::Borrowed` when the pattern does not match,
        // so only take (and keep) a new allocation when a redaction actually
        // happened. On the common no-secret path this avoids one String clone
        // per pattern (12+ per call), and this runs on every error/log line.
        if let Cow::Owned(replaced) = pattern.replace_all(&output, "[REDACTED]") {
            output = replaced;
        }
    }
    // Mask credentials embedded in URL userinfo, preserving scheme and host.
    if let Cow::Owned(replaced) = URL_USERINFO.replace_all(&output, "://***@") {
        output = replaced;
    }
    output
}
