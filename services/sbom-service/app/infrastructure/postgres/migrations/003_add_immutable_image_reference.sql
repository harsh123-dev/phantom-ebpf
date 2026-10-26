BEGIN;

ALTER TABLE sboms
    ADD COLUMN IF NOT EXISTS image_reference TEXT;

ALTER TABLE sboms
    DROP CONSTRAINT IF EXISTS sboms_image_reference_format;

ALTER TABLE sboms
    ADD CONSTRAINT sboms_image_reference_format
    CHECK (
        image_reference IS NULL
        OR image_reference ~ '^[A-Za-z0-9.-]+(:[0-9]+)?/[A-Za-z0-9._/-]+@sha256:[0-9a-f]{64}$'
    );

ALTER TABLE sboms
    DROP CONSTRAINT IF EXISTS sboms_image_reference_digest_match;

ALTER TABLE sboms
    ADD CONSTRAINT sboms_image_reference_digest_match
    CHECK (
        image_reference IS NULL
        OR right(image_reference, length(image_digest) + 1) = '@' || image_digest
    );

COMMIT;
