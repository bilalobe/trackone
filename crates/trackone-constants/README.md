# trackone-constants

**Component** providing shared configuration constants for the TrackOne Rust workspace.

## Purpose

`trackone-constants` holds workspace-wide constants that represent protocol and sizing policy decisions, such as:

- `MAX_FACT_LEN` — canonical maximum serialized length (bytes) of a `Fact` when encoded with postcard.

This crate exists so multiple crates (`trackone-core`, `trackone-gateway`, firmware crates) can share the same knobs without diverging magic numbers.

## C4: Responsibilities and Dependencies

- **Depends on**: none (intentionally minimal).
- **Used by**:
  - `trackone-core` (re-exports `MAX_FACT_LEN`).
  - Any other crate that needs to respect the same policy knobs.

## Policy Notes

- Constants in this crate are **policy**, not protocol physics. For example, `MAX_FACT_LEN` is chosen based on current payload shapes and can be increased in future versions.
