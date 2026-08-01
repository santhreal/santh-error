//! Intentionally failing tests that document missing features.
//!
//! These tests panic with a `Fix:` message describing what needs to be
//! implemented. They act as a living roadmap for the crate.

#[test]
#[should_panic(expected = "gap: typed error code registry not yet implemented")]
fn gap_typed_error_registry() {
    panic!("gap: typed error code registry not yet implemented");
}

#[test]
#[should_panic(expected = "gap: machine-readable error severity levels not yet implemented")]
fn gap_error_severity_levels() {
    panic!("gap: machine-readable error severity levels not yet implemented");
}

#[test]
#[should_panic(expected = "gap: structured error categories not yet implemented")]
fn gap_structured_error_categories() {
    panic!("gap: structured error categories not yet implemented");
}

#[test]
#[should_panic(expected = "gap: error code validation against known registry not yet implemented")]
fn gap_error_code_validation() {
    panic!("gap: error code validation against known registry not yet implemented");
}
