-- Bulk-updates STATUS_ID (plus optional COMMENTS + SUPPRESS_DATE) on an
-- explicit set of EXCEPTION rows.
--
-- Inputs:
--   P_EXCEPTION_IDS - comma-separated EXCEPTION_ID list. These are the
--                    rows the operator ticked in the Exceptions grid's
--                    bulk-selection column, and they are the ONLY rows
--                    touched. Replaced rule-name targeting, which
--                    matched every exception of a rule rather than the
--                    ones actually picked. Empty / NULL -> RETURN 0:
--                    an empty selection must never mean "all rows".
--   P_STATUS       - EXCEPTION_STATUS."NAME" (e.g. 'New', 'Accept',
--                    'Suppress', 'Override', 'Complete'). Unknown ->
--                    RETURN 0. Empty -> leave STATUS_ID alone, for a
--                    comments-only update.
--   P_COMMENTS     - text written to EXCEPTION.COMMENTS on every
--                    selected row. Pass '' to clear, NULL to leave
--                    existing comments untouched.
--   P_SUPPRESS_DATE - 'YYYY-MM-DD' string written to
--                    EXCEPTION.SUPPRESS_DATE on every selected row.
--                    Pass NULL or '' to leave existing suppress dates
--                    untouched (there is no bulk-clear affordance on
--                    the Bulk Status panel). Mandatory when P_STATUS
--                    is 'Suppress'.
--
-- Only current-day EXCEPTION rows are touched - the Bulk Status button
-- is gated to the current date on the client (see DqMonitorPage
-- showBulkAssign wiring), so this SP intentionally does not filter
-- EXCEPTION_DATE server-side; the client's gate is authoritative.
--
-- Returns the number of EXCEPTION rows updated.

CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_STATUS(
    P_EXCEPTION_IDS VARCHAR,
    P_STATUS       VARCHAR,
    P_COMMENTS     VARCHAR,
    P_SUPPRESS_DATE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    status_id NUMBER := NULL;
    now_ts    TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    affected  NUMBER := 0;
    -- Resolve to a DATE up front so the UPDATE stays flat. NULLIF turns
    -- '' into NULL so an empty string from the client is treated as
    -- "leave suppress_date untouched" (parity with COMMENTS).
    parsed_suppress DATE := TRY_TO_DATE(NULLIF(:P_SUPPRESS_DATE, ''));
BEGIN
    IF (:P_EXCEPTION_IDS IS NULL OR :P_EXCEPTION_IDS = '') THEN
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

    -- Mirror the per-row grid rule: any transition AWAY from 'New'
    -- (Accept / Override / Hold / Suppress / Research / Challenge /
    -- …) must carry an operator comment. In bulk we require the
    -- caller to pass a non-empty P_COMMENTS so every matched row
    -- gets a comment; without it, the audit trail on a triaged row
    -- would be empty. Comments-only updates (P_STATUS blank) bypass
    -- this check. Parity with SP_UPDATE_EXCEPTION_STATUS.
    IF (:P_STATUS IS NOT NULL AND :P_STATUS <> ''
        AND UPPER(:P_STATUS) <> 'NEW'
        AND (:P_COMMENTS IS NULL OR :P_COMMENTS = '')) THEN
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
           -- 'Hold' is a Suppress whose date the operator does not
           -- choose: always 2 business days out, computed server-side
           -- so the client cannot disagree about when a hold ends.
           -- Weekends only, no holiday calendar. Offsets by ISO
           -- weekday: Mon/Tue/Wed +2, Thu/Fri +4, Sat +3, Sun +2 - a
           -- Friday hold runs to Tuesday. Any passed suppress date is
           -- ignored for Hold on purpose.
           "SUPPRESS_DATE" = CASE
                                 WHEN :status_id IS NULL
                                     THEN "SUPPRESS_DATE"
                                 WHEN UPPER(:P_STATUS) = 'HOLD'
                                     THEN DATEADD(
                                              day,
                                              CASE DAYOFWEEKISO(TO_DATE(:now_ts))
                                                  WHEN 4 THEN 4
                                                  WHEN 5 THEN 4
                                                  WHEN 6 THEN 3
                                                  ELSE 2
                                              END,
                                              TO_DATE(:now_ts)
                                          )
                                 WHEN UPPER(:P_STATUS) = 'SUPPRESS'
                                     THEN COALESCE(:parsed_suppress, "SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           -- OPEN_DATE ratchets only when this bulk update flips the
           -- row TO 'New' AND it has no date yet. OPEN_DATE is
           -- write-once: it records the day an exception was FIRST
           -- surfaced, so an existing value is never overwritten, and a
           -- comments-only update (status_id NULL) never touches it.
           --
           -- 'Hold' no longer stamps it: hold release keys off
           -- SUPPRESS_DATE, not OPEN_DATE - see
           -- SP_EXPIRE_SUPPRESS_DATES. Parity with
           -- SP_UPDATE_EXCEPTION_STATUS.
           "OPEN_DATE"     = COALESCE(
                                 "OPEN_DATE",
                                 CASE
                                     WHEN :status_id IS NOT NULL
                                          AND UPPER(:P_STATUS) = 'NEW'
                                         THEN TO_DATE(:now_ts)
                                 END
                             ),
           -- CLOSE_DATE is a plain function of the status: the two
           -- CLOSED statuses ('Accept', 'Override') stamp today, every
           -- other status clears it. Parity with
           -- SP_UPDATE_EXCEPTION_STATUS.
           --
           -- The status_id IS NULL branch stays: a comments-only bulk
           -- update is not a status change and must leave CLOSE_DATE
           -- exactly as it found it.
           "CLOSE_DATE"    = CASE
                                 WHEN :status_id IS NULL
                                     THEN "CLOSE_DATE"
                                 WHEN UPPER(:P_STATUS) IN ('ACCEPT', 'OVERRIDE')
                                     THEN TO_DATE(:now_ts)
                                 ELSE NULL
                             END,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" IN (
        SELECT TRY_TO_NUMBER(TRIM(t.VALUE::STRING))
        FROM TABLE(SPLIT_TO_TABLE(:P_EXCEPTION_IDS, ',')) t
        WHERE TRY_TO_NUMBER(TRIM(t.VALUE::STRING)) IS NOT NULL
     );

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
