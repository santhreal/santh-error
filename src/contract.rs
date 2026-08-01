//! The fleet-wide error contract trait.
//!
//! [`SanthErrorContract`] lets any domain error enum render through the same
//! actionable-message formatter as the canonical [`SanthError`], without
//! folding its variants into a central type.

use std::borrow::Cow;

use crate::{compose_message, ErrorLocation, SanthError};

/// The Santh error contract: every Santh error answers the same questions -
/// *which* error it is ([`error_code`](Self::error_code)), *how to fix it*
/// ([`fix_hint`](Self::fix_hint), always starting with `"Fix: "`), and *what*
/// failed (`title` via [`Display`](std::fmt::Display)) - plus optional
/// `context` and `location`.
///
/// Domain crates keep their own error enums - their variants *are* their
/// behavior - and implement this trait to join the contract. They do **not**
/// fold their variants into [`SanthError`]: the trait gives one consistent
/// surface across the fleet without duplicating each crate's API upward. A
/// `thiserror`-style enum needs only `error_code` and `fix_hint`; the title
/// comes from `Display` and the rest defaults sensibly.
///
/// [`SanthError`] implements this trait, so the canonical type and every
/// domain error render identically via
/// [`actionable_message`](Self::actionable_message).
pub trait SanthErrorContract: std::error::Error {
    /// Stable, machine-readable error code, e.g. `"KEYHOG-E001"`.
    fn error_code(&self) -> &'static str;

    /// The actionable fix hint. Must start with `"Fix: "`.
    fn fix_hint(&self) -> Cow<'_, str>;

    /// One-line human-readable title. Defaults to the
    /// [`Display`](std::fmt::Display) output, which is correct for
    /// `thiserror`-style enums whose `Display` is the short message.
    fn title(&self) -> Cow<'_, str> {
        Cow::Owned(self.to_string())
    }

    /// Key-value diagnostic context. Empty by default.
    fn context(&self) -> Vec<(Cow<'static, str>, String)> {
        Vec::new()
    }

    /// Optional source or configuration location. `None` by default.
    fn location(&self) -> Option<&ErrorLocation> {
        None
    }

    /// Actionable, human-readable message: title, fix, context, location, and
    /// the source chain, with secrets redacted. The default matches
    /// [`SanthError`] exactly; override only for a custom layout.
    fn actionable_message(&self) -> String {
        let title = self.title();
        let fix = self.fix_hint();
        let context = self.context();
        compose_message(
            &title,
            &fix,
            &context,
            self.location(),
            std::error::Error::source(self),
        )
    }
}

impl SanthErrorContract for SanthError {
    fn error_code(&self) -> &'static str {
        self.code
    }

    fn fix_hint(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.fix)
    }

    fn title(&self) -> Cow<'_, str> {
        Cow::Borrowed(&self.title)
    }

    fn context(&self) -> Vec<(Cow<'static, str>, String)> {
        self.context.clone()
    }

    fn location(&self) -> Option<&ErrorLocation> {
        self.location.as_ref()
    }
}
