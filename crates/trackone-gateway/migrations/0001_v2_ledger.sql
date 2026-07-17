CREATE TABLE IF NOT EXISTS trackone_v2_ledger_state (
    ledger_id text PRIMARY KEY CHECK (ledger_id ~ '^[0-9a-f]{32}$'),
    revision numeric(20,0) NOT NULL CHECK (revision BETWEEN 0 AND 18446744073709551615),
    site_id text NOT NULL CHECK (site_id <> ''),
    next_segment_number numeric(20,0) NOT NULL CHECK (next_segment_number BETWEEN 0 AND 18446744073709551615),
    predecessor_cbor bytea,
    opened_at_ms numeric(20,0) NOT NULL CHECK (opened_at_ms BETWEEN 0 AND 18446744073709551615),
    clock_continuity_id numeric(39,0) NOT NULL CHECK (clock_continuity_id BETWEEN 0 AND 340282366920938463463374607431768211455),
    open_interval_ms numeric(20,0) NOT NULL CHECK (open_interval_ms BETWEEN 1 AND 18446744073709551615),
    open_batch_record_limit numeric(20,0) NOT NULL CHECK (open_batch_record_limit BETWEEN 1 AND 18446744073709551615),
    open_record_limit numeric(20,0) CHECK (open_record_limit BETWEEN 1 AND 18446744073709551615),
    open_size_limit_bytes numeric(20,0) CHECK (open_size_limit_bytes BETWEEN 1 AND 18446744073709551615),
    open_empty_mode text NOT NULL CHECK (open_empty_mode IN ('emit', 'suppress')),
    byte_count numeric(20,0) NOT NULL CHECK (byte_count BETWEEN 0 AND 18446744073709551615),
    next_interval_ms numeric(20,0) NOT NULL CHECK (next_interval_ms BETWEEN 1 AND 18446744073709551615),
    next_batch_record_limit numeric(20,0) NOT NULL CHECK (next_batch_record_limit BETWEEN 1 AND 18446744073709551615),
    next_record_limit numeric(20,0) CHECK (next_record_limit BETWEEN 1 AND 18446744073709551615),
    next_size_limit_bytes numeric(20,0) CHECK (next_size_limit_bytes BETWEEN 1 AND 18446744073709551615),
    next_empty_mode text NOT NULL CHECK (next_empty_mode IN ('emit', 'suppress'))
);

CREATE TABLE IF NOT EXISTS trackone_v2_active_epoch (
    site_id text PRIMARY KEY CHECK (site_id <> ''),
    ledger_id text NOT NULL UNIQUE CHECK (ledger_id ~ '^[0-9a-f]{32}$')
);

CREATE TABLE IF NOT EXISTS trackone_v2_open_record (
    ledger_id text NOT NULL REFERENCES trackone_v2_ledger_state(ledger_id) ON DELETE CASCADE,
    ordinal numeric(20,0) NOT NULL CHECK (ordinal BETWEEN 0 AND 18446744073709551615),
    record_cbor bytea NOT NULL,
    PRIMARY KEY (ledger_id, ordinal)
);

CREATE TABLE IF NOT EXISTS trackone_v2_sealed_segment (
    ledger_id text NOT NULL REFERENCES trackone_v2_ledger_state(ledger_id),
    segment_number numeric(20,0) NOT NULL CHECK (segment_number BETWEEN 0 AND 18446744073709551615),
    close_reason text NOT NULL CHECK (close_reason IN ('recovery', 'shutdown', 'reconfigure', 'size_limit', 'record_limit', 'interval', 'manual')),
    artifact_cbor bytea NOT NULL,
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    tsa_status text NOT NULL DEFAULT 'pending' CHECK (tsa_status IN ('pending', 'verified')),
    tsa_response bytea,
    PRIMARY KEY (ledger_id, segment_number)
);

ALTER TABLE trackone_v2_sealed_segment
    ADD COLUMN IF NOT EXISTS tsa_status text NOT NULL DEFAULT 'pending'
        CHECK (tsa_status IN ('pending', 'verified')),
    ADD COLUMN IF NOT EXISTS tsa_response bytea;

CREATE TABLE IF NOT EXISTS trackone_v2_sealed_record (
    ledger_id text NOT NULL,
    segment_number numeric(20,0) NOT NULL,
    ordinal numeric(20,0) NOT NULL CHECK (ordinal BETWEEN 0 AND 18446744073709551615),
    record_cbor bytea NOT NULL,
    PRIMARY KEY (ledger_id, segment_number, ordinal),
    FOREIGN KEY (ledger_id, segment_number)
        REFERENCES trackone_v2_sealed_segment(ledger_id, segment_number)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS trackone_v2_idempotency (
    ledger_id text NOT NULL REFERENCES trackone_v2_ledger_state(ledger_id) ON DELETE CASCADE,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 255),
    record_sha256 text NOT NULL CHECK (record_sha256 ~ '^[0-9a-f]{64}$'),
    admitted_segment_number numeric(20,0) NOT NULL CHECK (admitted_segment_number BETWEEN 0 AND 18446744073709551615),
    state_revision numeric(20,0) NOT NULL CHECK (state_revision BETWEEN 0 AND 18446744073709551615),
    sealed_segment_numbers text[] NOT NULL,
    PRIMARY KEY (ledger_id, idempotency_key)
);
