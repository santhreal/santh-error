#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]
//! `santh-error` - the shared error type for the Santh ecosystem.
//!
//! The single rule: **every error has a `Fix:` hint**.
//! No bare "parse error". No "something went wrong". Every error tells the
//! user what to do.
//!
//! # Quick start
//!
//! ```
//! use santh_error::SanthError;
//!
//! let err = SanthError::new("CFG-E001", "config file not found")
//!     .fix("Fix: create config.toml or pass --config")
//!     .build();
//! assert!(err.actionable_message().contains("Fix:"));
//! ```
//!
//! # Safe-defaults answers
//!
//! - Input size: operates only on in-memory strings supplied by the caller; it
//!   opens no files and imposes no size cap of its own, so memory use tracks
//!   the caller's message length.
//! - Recursion depth: error source chains are walked iteratively, never
//!   recursively, so a deep `source()` chain cannot overflow the stack.
//! - Outbound network: none. The crate performs no network access.
//! - Process spawning: none. The crate spawns no child processes.
//! - Filesystem writes: none. The crate reads and writes no files.
//! - Credential exposure: every rendered message is passed through
//!   [`redact_secrets`], so tokens, JWTs, and private keys are masked as
//!   `[REDACTED]` before they reach a log, error string, or temp file.

use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;

mod contract;
mod redact;
pub use contract::SanthErrorContract;
pub use redact::redact_secrets;

/// Location in source or configuration where an error occurred.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ErrorLocation {
    /// File or resource path.
    pub file: String,
    /// Line number, if known.
    pub line: Option<u32>,
    /// Column number, if known.
    pub column: Option<u32>,
}

impl ErrorLocation {
    /// Create a new [`ErrorLocation`] for the given file.
    pub fn new(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            line: None,
            column: None,
        }
    }

    /// Set the line number.
    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// Set the column number.
    #[must_use]
    pub fn with_column(mut self, column: u32) -> Self {
        self.column = Some(column);
        self
    }
}

/// Marker type indicating the builder has not yet received a fix hint.
#[derive(Debug)]
pub struct NoFix;

/// Marker type indicating the builder has received a fix hint.
#[derive(Debug)]
pub struct HasFix;

/// Builder for [`SanthError`].
///
/// Uses a typestate pattern to enforce at compile time that `.fix()` is
/// called before `.build()`.
#[derive(Debug)]
pub struct SanthErrorBuilder<State = NoFix> {
    code: &'static str,
    title: String,
    fix: Option<String>,
    context: Vec<(Cow<'static, str>, String)>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    location: Option<ErrorLocation>,
    _state: std::marker::PhantomData<State>,
}

/// Single owner of the `with_context` / `with_source` / `with_location`
/// diagnostic-mutator methods.
///
/// Both [`SanthErrorBuilder`] (during construction) and [`SanthError`]
/// (post-build enrichment) expose the identical builder-style mutators over
/// the same `context` / `source` / `location` fields. Rather than copy the
/// three bodies into both impl blocks (where they could silently drift), this
/// macro is the ONE place the semantics live; each impl invokes it once. Any
/// change to how context is pushed, how a source is boxed, or how a location
/// is attached happens here and propagates to both types.
macro_rules! impl_diagnostic_mutators {
    () => {
        /// Add a key-value diagnostic context entry.
        #[must_use]
        pub fn with_context(
            mut self,
            key: impl Into<Cow<'static, str>>,
            value: impl Display,
        ) -> Self {
            self.context.push((key.into(), value.to_string()));
            self
        }

        /// Attach a source error to the cause chain.
        #[must_use]
        pub fn with_source(
            mut self,
            source: impl std::error::Error + Send + Sync + 'static,
        ) -> Self {
            self.source = Some(Box::new(source));
            self
        }

        /// Attach a location to the error.
        #[must_use]
        pub fn with_location(mut self, location: ErrorLocation) -> Self {
            self.location = Some(location);
            self
        }
    };
}

impl<State> SanthErrorBuilder<State> {
    impl_diagnostic_mutators!();
}

impl SanthErrorBuilder<NoFix> {
    /// Provide the mandatory fix hint.
    ///
    /// Transitions the builder to the [`HasFix`] state, allowing `.build()`
    /// to be called.
    pub fn fix(self, fix: impl Into<String>) -> SanthErrorBuilder<HasFix> {
        SanthErrorBuilder {
            code: self.code,
            title: self.title,
            fix: Some(fix.into()),
            context: self.context,
            source: self.source,
            location: self.location,
            _state: std::marker::PhantomData,
        }
    }
}

impl SanthErrorBuilder<HasFix> {
    /// Build the [`SanthError`].
    ///
    /// A fix hint that does not already start with `"Fix: "` is normalised by
    /// prefixing it, so the built error always upholds the `"Fix: "` contract.
    /// This never panics.
    pub fn build(self) -> SanthError {
        // `fix` is always `Some` here: the `HasFix` typestate is only reachable
        // through `.fix()`, which sets it. `unwrap_or_default()` keeps the
        // impossible branch panic-free; a hint missing the contract prefix is
        // normalised to the "Fix: " prefix just below.
        let fix = self.fix.unwrap_or_default();
        let fix = if fix.starts_with("Fix: ") {
            fix
        } else {
            format!("Fix: {fix}")
        };
        SanthError {
            code: self.code,
            title: self.title,
            fix,
            context: self.context,
            source: self.source,
            location: self.location,
        }
    }
}

/// The shared error type for the Santh ecosystem.
///
/// Every error carries:
/// - A stable error `code`.
/// - A human-readable `title`.
/// - A **mandatory** `fix` hint starting with `"Fix: "`.
/// - Optional diagnostic `context`.
/// - An optional source error chain.
/// - An optional `location` in source or configuration.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct SanthError {
    code: &'static str,
    title: String,
    fix: String,
    context: Vec<(Cow<'static, str>, String)>,
    #[cfg_attr(feature = "serde", serde(skip))]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
    location: Option<ErrorLocation>,
}

impl SanthError {
    /// Start building a new [`SanthError`].
    ///
    /// The returned builder enforces at compile time that `.fix()` is called
    /// before `.build()`.
    // Intentionally returns a typestate builder, not `Self`: the `.fix()`
    // step is mandatory and enforced at compile time, so `new` cannot return
    // a finished `SanthError`. Renaming would break the public API (LAW 2).
    #[allow(clippy::new_ret_no_self)]
    pub fn new(code: &'static str, title: impl Into<String>) -> SanthErrorBuilder<NoFix> {
        SanthErrorBuilder {
            code,
            title: title.into(),
            fix: None,
            context: Vec::new(),
            source: None,
            location: None,
            _state: std::marker::PhantomData,
        }
    }

    /// Returns the stable error code, e.g. `"KEYHOG-E001"`.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the one-line title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the fix hint (including the `"Fix: "` prefix).
    pub fn fix_hint(&self) -> &str {
        &self.fix
    }

    /// Returns an actionable, human-readable message with all diagnostic details.
    ///
    /// Secrets are redacted from the output. The source chain is included
    /// so that causal information is never lost.
    ///
    /// Delegates to [`compose_message`], the single formatter shared with the
    /// default [`SanthErrorContract::actionable_message`], so the canonical
    /// type and any domain error enum that implements the contract render
    /// byte-identically.
    pub fn actionable_message(&self) -> String {
        compose_message(
            &self.title,
            &self.fix,
            &self.context,
            self.location.as_ref(),
            self.source
                .as_ref()
                .map(|s| s.as_ref() as &dyn std::error::Error),
        )
    }

    impl_diagnostic_mutators!();
}

/// Render the canonical Santh actionable message from its parts.
///
/// This is the single formatter shared by [`SanthError::actionable_message`]
/// and the default [`SanthErrorContract::actionable_message`], so the concrete
/// error type and any domain error enum that implements the contract produce
/// byte-identical output. Secrets are redacted last, after the full message
/// (title, fix, context, location, and source chain) is assembled.
/// Maximum number of `source()` links rendered in a "Caused by" chain. A
/// custom error type can return itself (or a very long chain) from
/// [`std::error::Error::source`]; walking that without a bound would loop
/// forever while the message string grows without limit. Past the cap the
/// chain is cut with an explicit truncation marker, so the diagnostic loss is
/// visible instead of silent.
const MAX_SOURCE_CHAIN: usize = 64;

pub(crate) fn compose_message(
    title: &str,
    fix: &str,
    context: &[(Cow<'static, str>, String)],
    location: Option<&ErrorLocation>,
    source: Option<&dyn std::error::Error>,
) -> String {
    let mut msg = String::with_capacity(256);
    msg.push_str(title);
    msg.push('\n');
    msg.push('\n');
    msg.push_str(fix);

    if !context.is_empty() {
        msg.push('\n');
        msg.push('\n');
        msg.push_str("Context:");
        for (k, v) in context {
            msg.push('\n');
            msg.push_str("  ");
            msg.push_str(k);
            msg.push_str(": ");
            msg.push_str(v);
        }
    }

    if let Some(loc) = location {
        msg.push('\n');
        msg.push('\n');
        msg.push_str("Location: ");
        msg.push_str(&loc.file);
        msg.push(':');
        msg.push_str(&loc.line.map_or_else(|| "?".to_string(), |l| l.to_string()));
        msg.push(':');
        msg.push_str(
            &loc.column
                .map_or_else(|| "?".to_string(), |c| c.to_string()),
        );
    }

    if let Some(source) = source {
        msg.push('\n');
        msg.push('\n');
        msg.push_str("Caused by:");
        let mut current: Option<&dyn std::error::Error> = Some(source);
        let mut links = 0usize;
        while let Some(err) = current {
            if links == MAX_SOURCE_CHAIN {
                msg.push('\n');
                msg.push_str("  - ... (source chain truncated after 64 links)");
                break;
            }
            msg.push('\n');
            msg.push_str("  - ");
            msg.push_str(&err.to_string());
            current = err.source();
            links += 1;
        }
    }

    redact_secrets(&msg)
}

impl PartialEq for SanthError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.title == other.title
            && self.fix == other.fix
            && self.context == other.context
            && self.location == other.location
    }
}

impl Eq for SanthError {}

impl fmt::Display for SanthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.actionable_message())
    }
}

impl std::error::Error for SanthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for SanthError {
    fn from(err: std::io::Error) -> Self {
        let (code, title, fix): (&'static str, &'static str, &'static str) = match err.kind() {
            std::io::ErrorKind::NotFound => (
                "SANTH-IO-NOTFOUND",
                "File or resource not found",
                "Fix: Verify the path exists and check for typos. If the file should be created automatically, ensure the parent directory exists.",
            ),
            std::io::ErrorKind::PermissionDenied => (
                "SANTH-IO-PERM",
                "Permission denied",
                "Fix: Check that the current user has read/write/execute permissions on the file or directory. On Unix, verify with `ls -la`.",
            ),
            std::io::ErrorKind::ConnectionRefused => (
                "SANTH-IO-CONNREF",
                "Connection refused",
                "Fix: Ensure the target service is running and listening on the expected port. Verify firewall rules and network connectivity.",
            ),
            std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe => (
                "SANTH-IO-CONNRESET",
                "Connection reset or broken pipe",
                "Fix: The remote peer closed the connection. Retry the operation and verify the remote service is stable.",
            ),
            std::io::ErrorKind::TimedOut => (
                "SANTH-IO-TIMEOUT",
                "I/O operation timed out",
                "Fix: Increase the timeout duration, check network latency, or verify the remote service is responsive.",
            ),
            std::io::ErrorKind::AlreadyExists => (
                "SANTH-IO-EXISTS",
                "File or resource already exists",
                "Fix: Remove the existing file, choose a different name, or open with overwrite/truncate flags if intended.",
            ),
            std::io::ErrorKind::InvalidInput => (
                "SANTH-IO-INVAL",
                "Invalid input parameter",
                "Fix: Check that all arguments to the I/O operation are valid and within supported ranges.",
            ),
            std::io::ErrorKind::UnexpectedEof => (
                "SANTH-IO-EOF",
                "Unexpected end of file",
                "Fix: The file is shorter than expected. Verify the file was written completely and was not truncated.",
            ),
            std::io::ErrorKind::OutOfMemory => (
                "SANTH-IO-NOMEM",
                "Out of memory",
                "Fix: Reduce memory usage, process data in smaller chunks, or allocate more RAM to the process.",
            ),
            _ => (
                "SANTH-IO-01",
                "I/O operation failed",
                "Fix: Check that the file or resource exists and that you have the correct permissions.",
            ),
        };

        Self::new(code, title).fix(fix).with_source(err).build()
    }
}

impl From<std::fmt::Error> for SanthError {
    fn from(err: std::fmt::Error) -> Self {
        Self::new("SANTH-FMT-01", "Formatting failed")
            .fix("Fix: Ensure all format arguments implement the required Display/Debug traits and match the format string.")
            .with_source(err)
            .build()
    }
}

impl From<std::string::FromUtf8Error> for SanthError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Self::new("SANTH-UTF8-01", "Invalid UTF-8 sequence")
            .fix("Fix: Ensure the input is valid UTF-8, or use String::from_utf8_lossy for lossy conversion.")
            .with_source(err)
            .build()
    }
}

impl From<regex::Error> for SanthError {
    fn from(err: regex::Error) -> Self {
        Self::new("SANTH-REGEX-01", "Regex compilation failed")
            .fix("Fix: Verify the regex pattern syntax and ensure all special characters are properly escaped.")
            .with_source(err)
            .build()
    }
}

// Rung 7 (contract): the README quick-start is a doctest, so a README example
// that drifts from the real API fails `cargo test` instead of misleading users.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}
