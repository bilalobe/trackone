-- Operational metadata only: sealed artifacts and retained responses are immutable.
ALTER TABLE trackone_vtl_sealed_segment
    ADD COLUMN IF NOT EXISTS tsa_attempt_count bigint NOT NULL DEFAULT 0 CHECK (tsa_attempt_count >= 0),
    ADD COLUMN IF NOT EXISTS tsa_next_attempt timestamptz DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS tsa_last_error text,
    ADD COLUMN IF NOT EXISTS tsa_lease_until timestamptz;
ALTER TABLE trackone_vtl_sealed_segment
    DROP CONSTRAINT IF EXISTS trackone_vtl_sealed_segment_tsa_status_check;
ALTER TABLE trackone_vtl_sealed_segment
    ADD CONSTRAINT trackone_vtl_sealed_segment_tsa_status_check
    CHECK (tsa_status IN ('queued', 'verified', 'failed'));
UPDATE trackone_vtl_sealed_segment SET tsa_next_attempt=NULL
    WHERE tsa_status <> 'queued' AND tsa_next_attempt IS NOT NULL;
CREATE INDEX IF NOT EXISTS trackone_vtl_timestamp_due
    ON trackone_vtl_sealed_segment (ledger_id, tsa_next_attempt, segment_number)
    WHERE tsa_status='queued';
