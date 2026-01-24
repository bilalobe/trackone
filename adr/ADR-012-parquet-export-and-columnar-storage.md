# ADR-012: Parquet Export for Telemetry Facts and Columnar Storage

**Status**: Proposed
**Date**: 2025-11-02

## Context

TrackOne currently emits canonical facts as JSON files and aggregates them into Merkle day records for verifiability and OTS anchoring. JSON is ideal as a canonical, human-auditable source of truth and for cryptographic determinism (ADR‑003), but it is not optimized for analytical scans at scale.

Operational needs emerging for M#>=2 include:

- Columnar analytics over large time ranges (filter, aggregate by device/site).
- Efficient storage for numeric metrics (temperature, humidity/bioimpedance, counters), with column pruning and compression.
- Optional downstream interoperability with engines like DuckDB/Polars/Spark/Trino.

Parquet addresses these by providing columnar storage, compression, encoding, and partition pruning, without changing the canonical JSON and Merkle/OTS integrity story.

## Decision

Introduce an optional “export-to-Parquet” capability that produces partitioned Parquet datasets derived from canonical fact JSONs. This is an additive feature; JSON remains the canonical format for hashing, Merkle roots, and OTS anchoring.

Key elements:

- Canonical source of truth remains canonical JSON (ADR‑003). Parquet is derivative.
- An exporter (e.g., `scripts/gateway/export_parquet.py`) reads `facts_dir` and writes Parquet under `out/<site>/parquet/` partitioned by time (and optionally `site_id`).
- Wide schema for fixed metrics; payload fields (e.g., `temp_c`, `bioimpedance`, `counter`, `status_flags`) are flattened into typed columns. Additional columns: `timestamp` (UTC), `device_id`, optional `site_id`, and `nonce` for lineage.
- Partitioning: `day=YYYY-MM-DD[/site_id=...]`. Future option to partition by hour when volume justifies it.
- Compression/encoding: Snappy by default; allow ZSTD. Dictionary encoding for low-cardinality columns (`device_id`, `site_id`).
- File sizing/compaction: target ~128–512 MB compressed per file per partition. Exporter compacts small JSON files into larger Parquet files.
- Optional dependencies: PyArrow or Polars. Exporter degrades gracefully (no-op) if deps are missing, avoiding impact to existing CI/tests.
- Zero impact to Merkle/OTS workflow: Parquet output is not hashed or anchored; day chaining semantics are unchanged.

Scope and non-goals (for >= 0.2.0):

- Scope: batch export jobs and local analytics; basic schema evolution (additive columns).
- Non-goals (initially): ACID table formats (Delta/Iceberg/Hudi), streaming upserts, and fast OLTP queries.

## Consequences

### Positive

- Significant gains in analytical performance via column pruning and compression.
- Reduced storage costs for numeric metrics compared to raw JSON.
- Broader tool compatibility (DuckDB/Polars/Spark/Trino/BigQuery external tables).
- Keeps security and verifiability guarantees intact by preserving JSON as canonical.

### Negative

- Additional code and dependencies (optional) for export and compaction.
- Operational complexity: partition management and small-file mitigation.
- Schema management: need a documented Parquet schema contract and evolution policy.

## Alternatives Considered

- Keep JSON only: simplest, but poor for analytical scans and storage efficiency.
- ORC instead of Parquet: also columnar; Parquet has broader ecosystem support for our stack.
- Time-series databases (TimescaleDB/InfluxDB/ClickHouse): excellent for low-latency TS queries, but introduces an online store, persistence/ops overhead, and doesn’t replace JSON+Merkle for verifiability; can be a serving layer later.
- Table formats (Delta/Iceberg/Hudi): powerful ACID and schema evolution, but higher operational complexity. Could be an incremental upgrade after Parquet is established.

## Testing & Migration

Validation strategy:

- Unit tests for exporter: schema mapping (JSON→columns), partition paths, compression, and idempotent writes.
- Golden tests comparing a small set of facts to expected Parquet schema/values (via PyArrow or Polars).
- Backfill tool (optional): export historical facts for selected days/sites; verify row counts vs JSON facts and spot-check aggregates.
- CI: keep exporter tests optional or mark to skip if Parquet deps are not installed; do not gate core CI on optional deps.

Migration plan:

- Phase 1 (>= 0.2.0): Ship exporter as optional CLI; document usage. No runtime impact.
- Phase 2: Add scheduled/automated export job, partition compaction, and basic retention guidance.
- Phase 3 (optional): Evaluate table formats (Delta/Iceberg/Hudi) if upserts/deletes or lakehouse semantics are required.

## Implementation Notes

- Suggested CLI (non-breaking):
  - `python scripts/gateway/export_parquet.py --facts <facts_dir> --out <out_dir> [--site <id>] [--date YYYY-MM-DD] [--compression {snappy,zstd}] [--partition-hourly]`
- Typed schema (initial wide columns):
  - `timestamp` (UTC), `device_id` (string), `site_id` (string, optional), `nonce` (string)
  - `temp_c` (float32), `bioimpedance` (float32 or int32 scaled), `counter` (uint32), `status_flags` (uint8)
- Schema evolution policy: additive columns only initially; document unit scaling if using integers for space/determinism.
- Backward compatibility: no change to JSON, Merkle, or OTS processes; Parquet is additive and can be disabled entirely.
