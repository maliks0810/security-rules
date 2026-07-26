-- Sweeps any EXCEPTION rows whose EXCEPTION_DATE is strictly older than
-- today into EXCEPTION_HIST, then deletes them from EXCEPTION so the
-- live table only ever holds the current day's rows. Every archived
-- row gets its own BATCH_ID computed per (RULE_ID, EXCEPTION_DATE):
--   BATCH_ID = MAX(HIST.BATCH_ID for that rule+date) + 1
-- — 1 the first time a given rule+date is archived, otherwise the
-- next increment. Different rules on the same date advance
-- independently: if rule A last archived to date X at batch 1 and
-- rule B at batch 2, a subsequent sweep lands rule A at batch 2 and
-- rule B at batch 3.
--
-- All rows for the same (rule, date) pair archived by a single sweep
-- share a batch id (the correlated subquery evaluates against HIST's
-- pre-INSERT snapshot).
--
-- Independent of any rule scope: this is pure housekeeping. Called
-- by an external cron, not from the /executeRules service path.
-- Returns the row count moved.

CREATE OR REPLACE PROCEDURE SP_ARCHIVE_STALE_DATES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    exc_today DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected  NUMBER := 0;
BEGIN
    INSERT INTO "EXCEPTION_HIST" (
        "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
        "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "SUPPRESS_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        e."EXCEPTION_ID", e."RULE_ID", e."ASSET_ID", e."EXCEPTION_DATE",
        COALESCE(
            (SELECT MAX(h."BATCH_ID") FROM "EXCEPTION_HIST" h
              WHERE h."EXCEPTION_DATE" = e."EXCEPTION_DATE"
                AND h."RULE_ID"        = e."RULE_ID"),
            0
        ) + 1 AS "BATCH_ID",
        e."ID_BB_GLOBAL", e."STATE_ID", e."STATUS_ID", e."COMMENTS",
        e."EXCEPTION_TIME", e."ISSUE_DESCRIPTION", e."RESULT_DATA",
        e."SUPPRESS_DATE", e."ASSIGN_TO_ID", e."RESULT_TYPE_ID",
        e."CREATED_DATE", e."CREATED_BY", e."MODIFIED_DATE", e."MODIFIED_BY"
    FROM "EXCEPTION" e
    WHERE e."EXCEPTION_DATE" < :exc_today;
    affected := SQLROWCOUNT;

    DELETE FROM "EXCEPTION" WHERE "EXCEPTION_DATE" < :exc_today;

    RETURN affected;
END;
$$;
