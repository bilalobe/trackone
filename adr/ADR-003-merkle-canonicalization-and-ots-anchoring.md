# ADR-003: Canonicalization, Merkle Policy, and Daily OpenTimestamps Anchoring

**Status:** Accepted  
**Date:** 2025-10-06

## Context

- We must produce a verifiable, reproducible daily commitment to all accepted device facts without publishing payloads
  on a public chain.
- Reviewers and auditors should be able to recompute roots and verify proofs on any machine and get identical results.
- Our test suite enforces deterministic canonical JSON, a stable Merkle policy, day-to-day chaining, and a simple
  anchor/verify workflow.

## Decision

### 1. Canonicalization (facts, blocks, day)

- **Encoding:** JSON, UTF‑8 bytes.
- **Canonicalization function:**  
  `json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf‑8")`
    - No whitespace, no pretty print; sorted keys at all nesting levels.
- **Numbers:** use JSON default encoding; determinism is guaranteed by value equality and sort_keys.

### 2. Merkle policy

- **Leaf bytes:** canonical JSON bytes of each fact.
- **Leaf hash:** `SHA‑256(leaf_bytes)` → hex string (lowercase).
- **Leaf ordering:** sort by leaf hash (lexicographic) to remove filesystem or ingestion order bias.
- **Tree construction:**
    - Start with the sorted leaf hashes (as bytes).
    - Pairwise concatenate (`a||b`) and hash SHA‑256 to form parent layer.
    - For odd layer length, duplicate the last hash.
    - Repeat until a single root remains.
- **Empty set:** `root = SHA‑256(b"")` (hex). Emitting an empty day requires an explicit flag (`--allow-empty`).

### 3. Block header (batch)

- For v1 we emit a single batch per day with:
    - `version` (int), `site_id` (string), `day` (YYYY‑MM‑DD), `batch_id` (string),
    - `merkle_root` (hex), `count` (int),
    - `leaf_hashes` (array of hex strings; auditor aid), `ots_proof` (nullable).
- **File:** `out/<site>/blocks/<day>-00.block.json`
- **Note:** leaf_hashes are an auditor convenience; not strictly required to recompute the daily root, but retained for
  traceability.

### 4. Day record and chaining

- **Day record fields (v1):**
    - `version`, `site_id`, `date`, `prev_day_root` (hex), `batches` (array of block headers), `day_root` (hex).
- `day_root` equals the Merkle root computed from the day’s facts.
- **Chaining:**
    - For the first day at a site, `prev_day_root = "00"*32`.
    - For subsequent days, `prev_day_root = previous day’s day_root` (from `day/<YYYY‑MM‑DD>.json`).
- **Artifacts:**
    - Binary canonical blob: `out/<site>/day/<day>.bin` (contains canonical JSON bytes of the day record).
    - Human‑readable: `out/<site>/day/<day>.json` (pretty JSON).
    - Convenience hash: `out/<site>/day/<day>.bin.sha256` (hex).

### 5. OpenTimestamps anchoring policy

- We anchor `SHA‑256(day.bin)` using OpenTimestamps (OTS):
    - Stamp on day rollover (e.g., 00:10 UTC) via `ots stamp <day.bin>`.
    - Keep the proof next to the blob: `<day>.bin.ots`.
    - Upgrade proofs weekly via `ots upgrade` to accumulate Bitcoin confirmations.
- **Verification:** `ots verify <day>.bin.ots` must succeed; auditors recompute `day_root` from facts and confirm
  `day.bin` consistency before verifying OTS.

### 6. File layout (site_demo shown; site_id may be included in path)