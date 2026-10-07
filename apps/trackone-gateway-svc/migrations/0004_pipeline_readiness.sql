-- Operational metadata only; commitment artifacts and timestamp responses are unchanged.
ALTER TABLE trackone_vtl_sealed_segment
    ADD COLUMN IF NOT EXISTS tsa_enqueued_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ADD COLUMN IF NOT EXISTS tsa_attached_at timestamptz;
CREATE INDEX IF NOT EXISTS trackone_vtl_timestamp_age
    ON trackone_vtl_sealed_segment (ledger_id, tsa_enqueued_at) WHERE tsa_status='queued';

CREATE INDEX IF NOT EXISTS trackone_vtl_timestamp_attachment
    ON trackone_vtl_sealed_segment (ledger_id, tsa_attached_at) WHERE tsa_attached_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS trackone_vtl_timestamp_failed
    ON trackone_vtl_sealed_segment (ledger_id) WHERE tsa_status='failed';
CREATE INDEX IF NOT EXISTS trackone_vtl_timestamp_retrying
    ON trackone_vtl_sealed_segment (ledger_id) WHERE tsa_status='queued' AND tsa_last_error IS NOT NULL;

CREATE TABLE IF NOT EXISTS trackone_vtl_pipeline_usage (
    ledger_id text PRIMARY KEY REFERENCES trackone_vtl_ledger_state(ledger_id) ON DELETE CASCADE,
    pending_timestamps numeric(20,0) NOT NULL DEFAULT 0 CHECK (pending_timestamps >= 0),
    retained_evidence_bytes numeric(20,0) NOT NULL DEFAULT 0 CHECK (retained_evidence_bytes >= 0)
);

-- migrate() holds writer locks before applying ALTER TABLE or backfilling usage.
INSERT INTO trackone_vtl_pipeline_usage (ledger_id, pending_timestamps, retained_evidence_bytes)
SELECT s.ledger_id,
    (SELECT count(*) FROM trackone_vtl_sealed_segment WHERE ledger_id=s.ledger_id AND tsa_status='queued'),
    COALESCE((SELECT sum(octet_length(record_cbor)::numeric) FROM trackone_vtl_open_record WHERE ledger_id=s.ledger_id), 0)
    + COALESCE((SELECT sum(octet_length(record_cbor)::numeric) FROM trackone_vtl_sealed_record WHERE ledger_id=s.ledger_id), 0)
    + COALESCE((SELECT sum(octet_length(artifact_cbor)::numeric + COALESCE(octet_length(tsa_response),0)) FROM trackone_vtl_sealed_segment WHERE ledger_id=s.ledger_id), 0)
FROM trackone_vtl_ledger_state s
WHERE NOT EXISTS (SELECT 1 FROM trackone_vtl_pipeline_usage u WHERE u.ledger_id=s.ledger_id)
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION trackone_vtl_initialize_usage() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO trackone_vtl_pipeline_usage (ledger_id) VALUES (NEW.ledger_id) ON CONFLICT DO NOTHING;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS trackone_vtl_initialize_usage ON trackone_vtl_ledger_state;
CREATE TRIGGER trackone_vtl_initialize_usage AFTER INSERT ON trackone_vtl_ledger_state
    FOR EACH ROW EXECUTE FUNCTION trackone_vtl_initialize_usage();

CREATE OR REPLACE FUNCTION trackone_vtl_account_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE delta numeric := 0; ledger text;
BEGIN
    IF TG_OP <> 'DELETE' THEN
        delta := octet_length(NEW.record_cbor); ledger := NEW.ledger_id;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        delta := delta - octet_length(OLD.record_cbor); ledger := OLD.ledger_id;
    END IF;
    UPDATE trackone_vtl_pipeline_usage SET retained_evidence_bytes=retained_evidence_bytes+delta WHERE ledger_id=ledger;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS trackone_vtl_account_record ON trackone_vtl_open_record;
CREATE TRIGGER trackone_vtl_account_record AFTER INSERT OR UPDATE OR DELETE ON trackone_vtl_open_record
    FOR EACH ROW EXECUTE FUNCTION trackone_vtl_account_record();
DROP TRIGGER IF EXISTS trackone_vtl_account_record ON trackone_vtl_sealed_record;
CREATE TRIGGER trackone_vtl_account_record AFTER INSERT OR UPDATE OR DELETE ON trackone_vtl_sealed_record
    FOR EACH ROW EXECUTE FUNCTION trackone_vtl_account_record();

CREATE OR REPLACE FUNCTION trackone_vtl_account_segment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE bytes numeric := 0; pending numeric := 0; ledger text;
BEGIN
    IF TG_OP <> 'DELETE' THEN
        bytes := octet_length(NEW.artifact_cbor)::numeric + COALESCE(octet_length(NEW.tsa_response),0);
        pending := CASE WHEN NEW.tsa_status='queued' THEN 1 ELSE 0 END; ledger := NEW.ledger_id;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        bytes := bytes - octet_length(OLD.artifact_cbor)::numeric - COALESCE(octet_length(OLD.tsa_response),0);
        pending := pending - CASE WHEN OLD.tsa_status='queued' THEN 1 ELSE 0 END; ledger := OLD.ledger_id;
    END IF;
    IF bytes <> 0 OR pending <> 0 THEN
        UPDATE trackone_vtl_pipeline_usage SET retained_evidence_bytes=retained_evidence_bytes+bytes,
            pending_timestamps=pending_timestamps+pending WHERE ledger_id=ledger;
    END IF;
    RETURN NULL;
END $$;
DROP TRIGGER IF EXISTS trackone_vtl_account_segment ON trackone_vtl_sealed_segment;
CREATE TRIGGER trackone_vtl_account_segment AFTER INSERT OR UPDATE OR DELETE ON trackone_vtl_sealed_segment
    FOR EACH ROW EXECUTE FUNCTION trackone_vtl_account_segment();
