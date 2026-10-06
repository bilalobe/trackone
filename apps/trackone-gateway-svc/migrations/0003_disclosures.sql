-- Complete snapshots become visible in one transaction. No update/upsert path.
CREATE TABLE IF NOT EXISTS trackone_vtl_disclosure (
    ledger_id text NOT NULL,
    segment_number numeric(20,0) NOT NULL,
    manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    manifest bytea NOT NULL,
    PRIMARY KEY (ledger_id, segment_number, manifest_sha256),
    FOREIGN KEY (ledger_id, segment_number)
        REFERENCES trackone_vtl_sealed_segment(ledger_id, segment_number)
);
CREATE TABLE IF NOT EXISTS trackone_vtl_disclosure_object (
    ledger_id text NOT NULL,
    segment_number numeric(20,0) NOT NULL,
    manifest_sha256 text NOT NULL,
    path text NOT NULL,
    bytes bytea NOT NULL,
    PRIMARY KEY (ledger_id, segment_number, manifest_sha256, path),
    FOREIGN KEY (ledger_id, segment_number, manifest_sha256)
        REFERENCES trackone_vtl_disclosure(ledger_id, segment_number, manifest_sha256)
);
