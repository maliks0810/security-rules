DROP FUNCTION IF EXISTS public."SP_DROP_CLOSED_EXCEPTIONS"(text, text);

-- Removes today's freshly produced EXCEPTION rows in scope that are still
-- closed - STATUS 'Accept' or 'Override' - more than one business day
-- after their CLOSE_DATE, so a closed exception stops being written once
-- the day after it was closed has passed.
--
-- Called by ExecuteRules AFTER insert -> inherit -> revert-to-new:
--   * inherit is what carries Accept / Override and CLOSE_DATE forward
--     from EXCEPTION_HIST, so the rows to drop only exist after it;
--   * the catalog's REVERT_TO_NEW_CRITERIA (e.g.
--     SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES) must get its say
--     first. A row it flips back to New is no longer closed, so it is
--     kept and shows up again.
-- A dropped row is never archived, so the last EXCEPTION_HIST row for
-- that (RULE_ID, ASSET_ID) stays the closed one. That keeps the next run
-- inheriting the closure - and keeps the revert function comparing its
-- values against the ones that were closed - until the values drift.
--
-- "More than one business day": dropped once today is past the first
-- business day after CLOSE_DATE. Weekends only, no holiday calendar
-- (same convention as the Hold date in SP_UPDATE_BULK_STATUS). Offsets
-- by ISO weekday of CLOSE_DATE: Mon-Thu +1, Fri +3, Sat +2, Sun +1. A
-- Monday close still shows Tuesday and drops Wednesday; a Friday close
-- still shows Monday and drops Tuesday.
--
-- Rows with no CLOSE_DATE are kept: there is nothing to measure from.
-- Only today's rows are touched, so an unswept older day is never
-- deleted without being archived.
--
-- Scope semantics match SP_ARCHIVE_EXCEPTIONS / SP_INHERIT_EXCEPTION_STATUSES.
-- Returns the number of rows dropped.
CREATE OR REPLACE FUNCTION public."SP_DROP_CLOSED_EXCEPTIONS"(
    p_rule_name text DEFAULT NULL,
    p_rule_type text DEFAULT NULL
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_today    date    := (NOW() AT TIME ZONE 'UTC')::date;
    v_affected integer := 0;
BEGIN
    DELETE FROM public."EXCEPTION" e
     WHERE e."EXCEPTION_DATE" = v_today
       AND e."CLOSE_DATE" IS NOT NULL
       AND e."STATUS_ID" IN (
           SELECT "EXCEPTION_STATUS_ID"
             FROM public."EXCEPTION_STATUS"
            WHERE "NAME" IN ('Accept', 'Override')
       )
       AND v_today > e."CLOSE_DATE"
                     + (CASE EXTRACT(ISODOW FROM e."CLOSE_DATE")
                            WHEN 5 THEN 3
                            WHEN 6 THEN 2
                            ELSE 1
                        END)::int
       AND e."RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM public."RULE" r
             JOIN public."RULE_CATALOG" rc    ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             LEFT JOIN public."RULE_GROUP" rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
            WHERE p_rule_name IS NULL
               OR p_rule_name = ''
               OR p_rule_name = 'All'
               OR (upper(COALESCE(p_rule_type, 'CATALOG')) = 'CATALOG'
                     AND rc."NAME" = p_rule_name)
               OR (upper(p_rule_type) = 'GROUP'
                     AND rg."NAME"  = p_rule_name)
               OR (upper(p_rule_type) = 'RULE'
                     AND r."RULE_NAME" = p_rule_name)
       );
    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
