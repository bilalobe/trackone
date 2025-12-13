# trackone-gateway

# Overview

`trackone-gateway` is the Rust cdylib that provides a Python extension exposing gateway-side operations.

## Purpose

- Bind `trackone-core` to Python via PyO3.
- Offer gateway-specific helpers (batching, Merkle root computation, anchoring integrations).
- Ship a Python wheel via `maturin` for use in downstream Python tooling.

## Responsibilities and dependencies

- Responsibilities:
  - Provide a stable, documented Python API that delegates heavy work to `trackone-core`.
  - Wrap host-only operations requiring `std`.
- Dependencies:
  - `trackone-core` with the `gateway` feature enabled.
  - `pyo3` for Python bindings.
- Consumers:
  - Python pipeline scripts and CI jobs.

## Architecture diagram

```mermaid
C4Context
    title trackone-gateway - Context
    Person(p1, "Operator", "Uses Python CLI and scripts to manage gateway operations")
    System(system, "Python Pipeline", "Existing Python pipeline that orchestrates ingestion and verification")
    Container(c1, "trackone-gateway (cdylib)", "Rust CDYLIB built with maturin", "Provides PyO3 bindings and gateway operations")
    Container(c2, "trackone-core", "Rust crate", "Core protocol, serialization, crypto abstractions")

    Rel(p1, system, "interacts with")
    Rel(system, c1, "loads/uses via Python import")
    Rel(c1, c2, "calls into")
```
