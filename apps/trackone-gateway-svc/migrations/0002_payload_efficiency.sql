-- Additive/idempotent migration for single and atomic-batch idempotency.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'trackone_v2_idempotency'
          AND column_name = 'record_sha256'
    ) THEN
        ALTER TABLE trackone_v2_idempotency
            RENAME COLUMN record_sha256 TO request_sha256;
    END IF;
END $$;

ALTER TABLE trackone_v2_idempotency
    ADD COLUMN IF NOT EXISTS admitted_segment_numbers text[];

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'trackone_v2_idempotency'
          AND column_name = 'admitted_segment_number'
    ) THEN
        UPDATE trackone_v2_idempotency
        SET admitted_segment_numbers = ARRAY[admitted_segment_number::text]
        WHERE admitted_segment_numbers IS NULL;
        ALTER TABLE trackone_v2_idempotency
            DROP COLUMN admitted_segment_number;
    END IF;
END $$;

ALTER TABLE trackone_v2_idempotency
    ALTER COLUMN admitted_segment_numbers SET NOT NULL;
