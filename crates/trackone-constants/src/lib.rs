/// Canonical maximum serialized length for a `Fact` in bytes.
///
/// This is a workspace-level policy knob. Consumers should not hardcode
/// their own value; import it from `trackone_core::MAX_FACT_LEN` (re-exported)
/// or directly from this crate if needed.
pub const MAX_FACT_LEN: usize = 256;
