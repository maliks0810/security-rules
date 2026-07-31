DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_STATUS"(text, text, text);
DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_STATUS"(text, text, text, text);

-- Bulk-updates STATUS_ID (plus optional COMMENTS + SUPPRESS_DATE) for
-- every EXCEPTION belonging to any of the passed rule names. Mirrors
-- SNOWFLAKE SP_UPDATE_BULK_STATUS. Pass NULL / '' for p_comments to
-- leave existing COMMENTS untouched; empty string clears them.
-- SUPPRESS_DATE handling depends on p_status:
--   'Suppress'  → use p_suppress_date if provided, else keep existing.
--   any other   → NULL out SUPPRESS_DATE. Moving an exception off
--                 Suppress makes the old suppression irrelevant, so
--                 the date is cleared automatically.
-- Rule names are a comma-joined string (matches the SNOWFLAKE
-- contract).
CREATE OR REPLACE FUNCTION public."SP_UPDATE_BULK_STATUS"(
    p_rule_names    text,
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
    v_names     text[];
    v_affected  integer := 0;
    -- Resolve to a DATE up front. NULLIF('') → NULL so an empty
    -- suppress_date string is treated as "leave untouched" (parity
    -- with COMMENTS). The COALESCE in the UPDATE then preserves the
    -- existing SUPPRESS_DATE when v_suppress is NULL.
    v_suppress  date := NULLIF(p_suppress_date, '')::date;
BEGIN
    IF p_rule_names IS NULL OR p_rule_names = '' THEN
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
    -- become empty rule-name lookups.
    SELECT ARRAY(
        SELECT btrim(t.name)
        FROM unnest(string_to_array(p_rule_names, ',')) AS t(name)
        WHERE btrim(t.name) <> ''
    ) INTO v_names;

    IF v_names IS NULL OR array_length(v_names, 1) IS NULL THEN
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
           "SUPPRESS_DATE" = CASE
                                 WHEN v_status_id IS NULL
                                     THEN e."SUPPRESS_DATE"
                                 WHEN upper(p_status) = 'SUPPRESS'
                                     THEN COALESCE(v_suppress, e."SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           "MODIFIED_DATE" = v_now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM public."RULE" r
        WHERE r."RULE_NAME" = ANY(v_names)
     );

    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
