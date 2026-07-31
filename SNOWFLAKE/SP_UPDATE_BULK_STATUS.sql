-- Bulk-updates STATUS_ID (plus optional COMMENTS + SUPPRESS_DATE) for
-- every EXCEPTION belonging to any of the passed rule names.
--
-- Inputs:
--   P_RULE_NAMES    — comma-separated RULE_NAME list (same shape as
--                     SP_UPDATE_BULK_ASSIGN).
--   P_STATUS        — EXCEPTION_STATUS."NAME" (e.g. 'New', 'Accept',
--                     'Suppress', 'Override', 'Complete'). Unknown /
--                     empty → RETURN 0, no writes.
--   P_COMMENTS      — text written to EXCEPTION.COMMENTS on every
--                     matched row. Pass '' to clear, NULL to leave
--                     existing comments untouched.
--   P_SUPPRESS_DATE — 'YYYY-MM-DD' string written to
--                     EXCEPTION.SUPPRESS_DATE on every matched row.
--                     Pass NULL or '' to leave existing suppress
--                     dates untouched (Bulk Status panel has no
--                     bulk-clear affordance).
--
-- Only current-day EXCEPTION rows are touched — the Bulk Status
-- button is gated to the current date on the client (see
-- DqMonitorPage showBulkAssign wiring), so this SP intentionally
-- does not filter EXCEPTION_DATE server-side; the client's gate is
-- authoritative.
--
-- Returns the number of EXCEPTION rows updated.

CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_STATUS(
    P_RULE_NAMES   VARCHAR,
    P_STATUS       VARCHAR,
    P_COMMENTS     VARCHAR,
    P_SUPPRESS_DATE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    status_id NUMBER := NULL;
    now_ts    TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    affected  NUMBER := 0;
    -- Resolve to a DATE up front so the UPDATE stays flat. NULLIF
    -- turns '' into NULL so an empty string from the client is
    -- treated as "leave suppress_date untouched" (parity with
    -- COMMENTS).
    parsed_suppress DATE := TRY_TO_DATE(NULLIF(:P_SUPPRESS_DATE, ''));
BEGIN
    IF (:P_RULE_NAMES IS NULL OR :P_RULE_NAMES = '') THEN
        RETURN 0;
    END IF;

    -- P_STATUS is now optional — Bulk Status can be used to update
    -- only COMMENTS (via the "Clear Comments" checkbox or a typed
    -- value). Reject only when the caller asked for nothing at all:
    -- no status, no comment change, no suppress date.
    IF ( (:P_STATUS IS NULL OR :P_STATUS = '')
         AND :P_COMMENTS IS NULL
         AND :parsed_suppress IS NULL
       ) THEN
        RETURN 0;
    END IF;

    -- Mirror the per-row grid rule (see ExceptionsTable status
    -- <select> onChange): moving an exception INTO 'Suppress'
    -- requires a Suppress Date. In bulk we can't rely on per-row
    -- existing dates because some rows may have never been
    -- suppressed. Require the caller to pass P_SUPPRESS_DATE
    -- explicitly and reject otherwise. The frontend disables the
    -- Update Status/Comments button in the same state; this is the
    -- server-side safety net.
    IF (UPPER(:P_STATUS) = 'SUPPRESS' AND :parsed_suppress IS NULL) THEN
        RETURN 0;
    END IF;

    -- Only resolve the status id when a status was actually passed.
    -- A blank P_STATUS means "leave STATUS_ID alone", so we skip the
    -- lookup and let status_id stay NULL for the COALESCE below.
    IF (:P_STATUS IS NOT NULL AND :P_STATUS <> '') THEN
        SELECT "EXCEPTION_STATUS_ID" INTO :status_id
        FROM "EXCEPTION_STATUS"
        WHERE "NAME" = :P_STATUS
        LIMIT 1;

        IF (:status_id IS NULL) THEN
            RETURN 0;
        END IF;
    END IF;

    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = COALESCE(:status_id, "STATUS_ID"),
           "COMMENTS"      = COALESCE(:P_COMMENTS, "COMMENTS"),
           -- SUPPRESS_DATE handling:
           --   status change absent  → leave the date alone (a
           --     comments-only update must not disturb Suppress rows).
           --   status becomes 'Suppress' → use the passed date, else
           --     keep the existing one.
           --   any other status      → NULL out the date so the grid
           --     never shows a stale suppression next to a
           --     non-Suppress row.
           "SUPPRESS_DATE" = CASE
                                 WHEN :status_id IS NULL
                                     THEN "SUPPRESS_DATE"
                                 WHEN UPPER(:P_STATUS) = 'SUPPRESS'
                                     THEN COALESCE(:parsed_suppress, "SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE "RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM LATERAL SPLIT_TO_TABLE(:P_RULE_NAMES, ',') t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name
     );

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
