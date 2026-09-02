DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_STATUS"(text, text, text);
DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_STATUS"(text, text, text, text);

-- Bulk-updates STATUS_ID (plus optional COMMENTS + SUPPRESS_DATE) on an
-- explicit set of EXCEPTION rows - the ones the operator ticked in the
-- Exceptions grid's bulk-selection column, named outright by
-- p_exception_ids. Mirrors SNOWFLAKE SP_UPDATE_BULK_STATUS. Pass
-- NULL / '' for p_comments to leave existing COMMENTS untouched; empty
-- string clears them.
-- SUPPRESS_DATE handling depends on p_status:
--   'Suppress'  → use p_suppress_date if provided, else keep existing.
--   any other   → NULL out SUPPRESS_DATE. Moving an exception off
--                 Suppress makes the old suppression irrelevant, so
--                 the date is cleared automatically.
-- Exception ids are a comma-joined string (matches the SNOWFLAKE
-- contract). An empty list updates nothing - it must never be read as
-- "every row".
CREATE OR REPLACE FUNCTION public."SP_UPDATE_BULK_STATUS"(
    p_exception_ids text,
    p_status        text,
    p_comments      text,
    p_suppress_date text DEFAULT NULL
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_status_id integer;
    v_now_ts    timestamp := (NOW() AT TIME ZONE 'UTC');
    v_ids       bigint[];
    v_affected  integer := 0;
    -- Resolve to a DATE up front. NULLIF('') → NULL so an empty
    -- suppress_date string is treated as "leave untouched" (parity
    -- with COMMENTS). The COALESCE in the UPDATE then preserves the
    -- existing SUPPRESS_DATE when v_suppress is NULL.
    v_suppress  date := NULLIF(p_suppress_date, '')::date;
BEGIN
    IF p_exception_ids IS NULL OR p_exception_ids = '' THEN
        RETURN 0;
    END IF;

    -- p_status is now optional — Bulk Status can be used to update
    -- only COMMENTS (via the "Clear Comments" checkbox or a typed
    -- value). Reject only when the caller asked for nothing at all:
    -- no status, no comment change, no suppress date.
    IF (p_status IS NULL OR p_status = '')
       AND p_comments IS NULL
       AND v_suppress IS NULL THEN
        RETURN 0;
    END IF;

    -- Mirror the per-row grid rule (see ExceptionsTable status
    -- <select> onChange): moving an exception INTO 'Suppress'
    -- requires a Suppress Date. In bulk we can't rely on per-row
    -- existing dates because some rows may have never been
    -- suppressed. Require the caller to pass p_suppress_date
    -- explicitly and reject otherwise. Frontend disables the
    -- Update Status/Comments button in the same state; this is the
    -- server-side safety net.
    IF upper(p_status) = 'SUPPRESS' AND v_suppress IS NULL THEN
        RETURN 0;
    END IF;

    -- Mirror the per-row grid rule: any transition AWAY from 'New'
    -- (Accept / Override / Hold / Suppress / Research / Challenge /
    -- …) must carry an operator comment. In bulk we require the
    -- caller to pass a non-empty p_comments so every matched row
    -- gets a comment; without it, the audit trail on a triaged row
    -- would be empty. Comments-only updates (p_status blank) bypass
    -- this check. Parity with SP_UPDATE_EXCEPTION_STATUS.
    IF p_status IS NOT NULL AND p_status <> ''
       AND upper(p_status) <> 'NEW'
       AND (p_comments IS NULL OR p_comments = '') THEN
        RETURN 0;
    END IF;

    -- Only resolve the status id when a status was actually passed.
    -- A blank p_status means "leave STATUS_ID alone", so we skip the
    -- lookup and let v_status_id stay NULL for the COALESCE below.
    IF p_status IS NOT NULL AND p_status <> '' THEN
        SELECT "EXCEPTION_STATUS_ID" INTO v_status_id
        FROM public."EXCEPTION_STATUS"
        WHERE "NAME" = p_status
        LIMIT 1;

        IF v_status_id IS NULL THEN
            RETURN 0;
        END IF;
    END IF;

    -- Trim + drop empty tokens so trailing / adjacent commas don't
    -- become empty id lookups. Non-numeric tokens are dropped rather
    -- than raising: the client only ever sends digits, and a cast error
    -- here would fail the whole batch over one malformed token.
    SELECT ARRAY(
        SELECT btrim(t.id)::bigint
        FROM unnest(string_to_array(p_exception_ids, ',')) AS t(id)
        WHERE btrim(t.id) ~ '^[0-9]+$'
    ) INTO v_ids;

    IF v_ids IS NULL OR array_length(v_ids, 1) IS NULL THEN
        RETURN 0;
    END IF;

    UPDATE public."EXCEPTION" e
       SET "STATUS_ID"     = COALESCE(v_status_id, e."STATUS_ID"),
           "COMMENTS"      = COALESCE(p_comments, e."COMMENTS"),
           -- SUPPRESS_DATE handling:
           --   status change absent  → leave the date alone (a
           --     comments-only update must not disturb Suppress rows).
           --   status becomes 'Suppress' → use the passed date, else
           --     keep the existing one.
           --   any other status      → NULL out the date so the grid
           --     never shows a stale suppression next to a
           --     non-Suppress row.
           -- 'Hold' is a Suppress whose date the operator does not
           -- choose: always 2 business days out, computed server-side.
           -- Weekends only, no holiday calendar. Offsets by ISO
           -- weekday: Mon/Tue/Wed +2, Thu/Fri +4, Sat +3, Sun +2 - a
           -- Friday hold runs to Tuesday. Any passed date is ignored.
           "SUPPRESS_DATE" = CASE
                                 WHEN v_status_id IS NULL
                                     THEN e."SUPPRESS_DATE"
                                 WHEN upper(p_status) = 'HOLD'
                                     THEN v_now_ts::date
                                          + (CASE EXTRACT(ISODOW FROM v_now_ts::date)
                                                 WHEN 4 THEN 4
                                                 WHEN 5 THEN 4
                                                 WHEN 6 THEN 3
                                                 ELSE 2
                                             END)::int
                                 WHEN upper(p_status) = 'SUPPRESS'
                                     THEN COALESCE(v_suppress, e."SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           -- OPEN_DATE ratchets only when this bulk update flips the
           -- row TO 'New'. Comments-only updates (v_status_id NULL) and
           -- transitions to any other status preserve the last-New date.
           -- 'Hold' stamps it too: SP_EXPIRE_SUPPRESS_DATES counts 2
           -- business days forward from OPEN_DATE, so it has to mean
           -- "the day this hold started".
           "OPEN_DATE"     = CASE
                                 WHEN v_status_id IS NOT NULL
                                      AND upper(p_status) IN ('NEW', 'HOLD')
                                     THEN v_now_ts::date
                                 ELSE e."OPEN_DATE"
                             END,
           -- CLOSE_DATE stamps today when this bulk update flips the
           -- row TO 'Accept' or 'Research'. Comments-only updates and
           -- transitions to any other status preserve the previous
           -- CLOSE_DATE (parity with SP_UPDATE_EXCEPTION_STATUS).
           "CLOSE_DATE"    = CASE
                                 WHEN v_status_id IS NOT NULL
                                      AND upper(p_status) IN ('ACCEPT', 'RESEARCH')
                                     THEN v_now_ts::date
                                 -- Transitions to 'New' / 'Suppress' /
                                 -- 'Challenge' put the row back into
                                 -- an unresolved / pending state; the
                                 -- historical close date is no longer
                                 -- valid.
                                 -- Hold joins them: a held row is
                                 -- pending, not closed.
                                 WHEN v_status_id IS NOT NULL
                                      AND upper(p_status) IN ('NEW', 'SUPPRESS', 'CHALLENGE', 'HOLD')
                                     THEN NULL
                                 ELSE e."CLOSE_DATE"
                             END,
           "MODIFIED_DATE" = v_now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."EXCEPTION_ID" = ANY(v_ids);

    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
