-- Runtime observations may be contract-conforming and therefore have no
-- violations. Keep those observations in the durable event stream without
-- manufacturing a violation solely to satisfy the original check constraint.
BEGIN;

ALTER TABLE drift_events
    DROP CONSTRAINT IF EXISTS drift_events_violation_count_range;

ALTER TABLE drift_events
    ADD CONSTRAINT drift_events_violation_count_range
        CHECK (violation_count >= 0 AND violation_count <= 64);

INSERT INTO schema_migrations (version, description)
VALUES (7, 'allow runtime observations with zero contract violations')
ON CONFLICT (version) DO NOTHING;

COMMIT;
