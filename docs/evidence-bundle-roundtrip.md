# Detached Evidence-Bundle Verification Round-Trip

## Purpose

This manuscript records a real detached verification round-trip for a Git-published
TrackOne evidence bundle.

The goal was to prove that:

- a day-scoped evidence set can be published into a signed Git repository;
- the repository can be exported as a `git bundle` for offline transport; and
- [verify_cli.py](../scripts/gateway/verify_cli.py) can verify the imported bundle
  from artifact paths alone, without consulting Git metadata.

This is the operational acceptance test for the boundary described in
[ADR-045](../adr/ADR-045-git-signed-evidence-distribution-plane.md).

In this document, `day/` is treated as the day evidence set / anchoring set for
the published bundle. The OTS metadata file `*.ots.meta.json` is part of that
set, not a detached sidecar living elsewhere in the workspace.

## Methodology

### 1. Run the pipeline

The normal demo pipeline was executed from the TrackOne repository root:

```bash
tox -e pipeline
```

Observed outcome:

- pipeline completed successfully in `warn` mode;
- `out/site_demo/` was regenerated;
- the day artifact date was `2025-10-07`;
- OTS anchoring remained incomplete/pending, which is expected for a fresh proof.

### 2. Create a dedicated evidence repository

The target evidence repository did not already exist, so it was created as a new
Git repository at:

```text
/home/beb/GolandProjects/trackone-evidence
```

### 3. Copy the curated subset

The workspace output was copied into a day-scoped publication layout:

```bash
mkdir -p trackone-evidence/site/an-001/day/2025-10-07
rsync -a --delete \
  --exclude='device_table.json' \
  --exclude='audit/' \
  out/site_demo/ \
  trackone-evidence/site/an-001/day/2025-10-07/
```

This preserved:

- `facts/`
- `blocks/`
- `day/`
- `provisioning/`
- `sensorthings/`
- `frames.ndjson`

and excluded:

- `device_table.json`
- `audit/`

Note:

- because the copy used only the exclusions above, `frames.ndjson` remained in the
  published set;
- if raw framed-input disclosure is not wanted, exclude `frames.ndjson` too or use
  [export_release.py](../scripts/evidence/export_release.py).

### 4. Sign the commit and tag the day boundary

Inside the evidence repository:

```bash
git add .
git commit -S -m "evidence: an-001 2025-10-07"
git tag -s evidence/an-001/2025-10-07 -m "evidence: an-001 2025-10-07"
```

Observed results:

- signed commit created:

  ```text
  bf8ef8db3d396b724703ac7ecdc00df95ff399e6
  ```

- signed tag created:

  ```text
  evidence/an-001/2025-10-07
  ```

- both signatures verified successfully with `git log --show-signature -1` and
  `git tag -v evidence/an-001/2025-10-07`

### 5. Export the repository as a bundle

```bash
git bundle create evidence-an-001-2025-10-07.bundle --all
```

Observed artifact:

```text
/home/beb/GolandProjects/trackone-evidence/evidence-an-001-2025-10-07.bundle
```

### 6. Clone from the bundle and verify detached contents

The bundle was cloned into a temporary directory and verified using the imported
artifact tree only:

```bash
git clone /home/beb/GolandProjects/trackone-evidence/evidence-an-001-2025-10-07.bundle "$CLONE_DIR"

python scripts/gateway/verify_cli.py \
  --root "$CLONE_DIR/site/an-001/day/2025-10-07" \
  --facts "$CLONE_DIR/site/an-001/day/2025-10-07/facts" \
  --json
```

## Result Output

Verifier exit code:

```text
4
```

Verifier JSON summary:

```json
{
  "artifacts": {
    "block": ".../blocks/2025-10-07-00.block.json",
    "day_cbor": ".../day/2025-10-07.cbor",
    "day_ots": ".../day/2025-10-07.cbor.ots",
    "verification_manifest": ".../day/2025-10-07.verify.json"
  },
  "channels": {
    "ots": {
      "enabled": true,
      "reason": "ots-binary-not-found",
      "status": "failed"
    },
    "peers": {
      "enabled": false,
      "reason": "disabled",
      "status": "skipped"
    },
    "tsa": {
      "enabled": false,
      "reason": "disabled",
      "status": "skipped"
    }
  },
  "checks": {
    "artifact_valid": true,
    "meta_valid": true,
    "root_match": true
  },
  "checks_executed": [
    "day_artifact_validation",
    "verification_manifest_validation",
    "batch_metadata_validation",
    "fact_level_recompute",
    "ots_verification"
  ],
  "checks_skipped": [],
  "overall": "failed",
  "policy": {
    "mode": "warn"
  },
  "manifest": {
    "schema": "verify_manifest",
    "source": "2025-10-07.verify.json",
    "status": "present"
  },
  "verification": {
    "commitment_profile_id": "trackone-canonical-cbor-v1",
    "disclosure_class": "A",
    "disclosure_label": "public-recompute",
    "publicly_recomputable": true
  }
}
```

Imported bundle tree used for verification:

```text
site/an-001/day/2025-10-07/
  blocks/2025-10-07-00.block.json
  day/2025-10-07.cbor
  day/2025-10-07.cbor.ots
  day/2025-10-07.cbor.sha256
  day/2025-10-07.json
  day/2025-10-07.ots.meta.json
  day/2025-10-07.verify.json
  facts/
  provisioning/
  sensorthings/
  frames.ndjson
```

## Interpretation

The detached verification round-trip succeeded in the sense intended by
[ADR-045](../adr/ADR-045-git-signed-evidence-distribution-plane.md):

- the evidence set was cloned from a `git bundle`;
- verification ran against the imported files directly;
- the verifier did not need repository refs, commit IDs, tag names, or Git
  signatures to evaluate artifact validity.

The non-zero exit code does **not** indicate a Merkle or manifest failure.
The key validation results were:

- `artifact_valid: true`
- `meta_valid: true`
- `root_match: true`
- `publicly_recomputable: true`

The failure came from the OTS channel only:

```json
"ots": {
  "enabled": true,
  "reason": "ots-binary-not-found",
  "status": "failed"
}
```

So the detached round-trip demonstrated the intended verifier boundary:

- artifact and manifest verification remained valid after offline Git transport;
- the proof bundle remained self-contained;
- Git acted as a transport/publication layer, not as a proof oracle.

## Conclusion

This round-trip is a concrete operational proof that TrackOne can:

1. publish a curated day evidence set into a signed Git history;
1. transport it offline via `git bundle`; and
1. verify the imported contents without making the verifier Git-aware.

That is the core effectivity gain of ADR-045 over a purely local `out/site_demo/`
workflow.
