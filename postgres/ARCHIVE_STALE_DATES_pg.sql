DROP FUNCTION IF EXISTS public."SP_ARCHIVE_STALE_DATES"();

-- Sweeps any EXCEPTION rows whose EXCEPTION_DATE is strictly older than
-- today into EXCEPTION_HIST, then deletes them from EXCEPTION so the
-- live table only ever holds the current day's rows. Every archived
-- row gets its own BATCH_ID computed per (RULE_ID, EXCEPTION_DATE):
-- MAX(HIST.BATCH_ID for that rule+date) + 1 — different rules on the
-- same date advance independently. All rows for the same (rule, date)
-- pair moved by a single sweep share a batch id.
--
-- Housekeeping only — no rule scope. Called by an external cron, not
-- from /executeRules.
CREATE OR REPLACE FUNCTION public."SP_ARCHIVE_STALE_DATES"()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    exc_today date    := (NOW() AT TIME ZONE 'UTC')::date;
    affected  integer := 0;
BEGIN
    WITH moved AS (
        DELETE FROM public."EXCEPTION"
         WHERE "EXCEPTION_DATE" < exc_today
        RETURNING *
    )
    INSERT INTO public."EXCEPTION_HIST" (
        "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
        "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "SUPPRESS_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        m."EXCEPTION_ID", m."RULE_ID", m."ASSET_ID", m."EXCEPTION_DATE",
        COALESCE(
            (SELECT MAX(h."BATCH_ID") FROM public."EXCEPTION_HIST" h
              WHERE h."EXCEPTION_DATE" = m."EXCEPTION_DATE"
                AND h."RULE_ID"        = m."RULE_ID"),
            0
        ) + 1 AS "BATCH_ID",
        m."ID_BB_GLOBAL", m."STATE_ID", m."STATUS_ID", m."COMMENTS",
        m."EXCEPTION_TIME", m."ISSUE_DESCRIPTION", m."RESULT_DATA",
        m."SUPPRESS_DATE", m."ASSIGN_TO_ID", m."RESULT_TYPE_ID",
        m."CREATED_DATE", m."CREATED_BY", m."MODIFIED_DATE", m."MODIFIED_BY"
      FROM moved m;

    GET DIAGNOSTICS affected = ROW_COUNT;
    RETURN affected;
END;
$$;
