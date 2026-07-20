-- Drop the retired outright-delete SP so a redeploy against a legacy
-- SF instance ends up with only SP_ARCHIVE_EXCEPTIONS. IF EXISTS makes
-- this a no-op on a fresh install.
DROP PROCEDURE IF EXISTS SP_DELETE_EXCEPTIONS(VARCHAR, VARCHAR);

-- Moves today's EXCEPTION rows in scope into EXCEPTION_HIST (stamping a
-- per-date BATCH_ID) instead of deleting them outright. Scope semantics
-- match SP_GET_RULES / the retired SP_DELETE_EXCEPTIONS:
--   P_RULE_TYPE = 'CATALOG' or 'RULE'  â†’ P_RULE_NAME = RULE_CATALOG.NAME
--   P_RULE_TYPE = 'GROUP'              â†’ P_RULE_NAME = RULE_GROUP.NAME
--   P_RULE_NAME NULL / empty / 'All'   â†’ every catalog (full archive of today)
--
-- BATCH_ID is per EXCEPTION_DATE. First run of a day starts at 1;
-- subsequent same-day runs increment. A new day resets the counter
-- because MAX() over that date returns NULL.
--
-- Returns the row count moved (matches the old SP_DELETE_EXCEPTIONS
-- contract so callers can log an "archived N" line).

CREATE OR REPLACE PROCEDURE SP_ARCHIVE_EXCEPTIONS(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    exc_date   DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    next_batch NUMBER := 0;
    affected   NUMBER := 0;
BEGIN
    next_batch := COALESCE(
        (SELECT MAX("BATCH_ID") FROM "EXCEPTION_HIST"
          WHERE "EXCEPTION_DATE" = :exc_date), 0
    ) + 1;

    INSERT INTO "EXCEPTION_HIST" (
        "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
        "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "SUPPRESS_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        e."EXCEPTION_ID", e."RULE_ID", e."ASSET_ID", e."EXCEPTION_DATE", :next_batch,
        e."ID_BB_GLOBAL", e."STATE_ID", e."STATUS_ID", e."COMMENTS",
        e."EXCEPTION_TIME", e."ISSUE_DESCRIPTION", e."RESULT_DATA",
        e."SUPPRESS_DATE", e."ASSIGN_TO_ID", e."RESULT_TYPE_ID",
        e."CREATED_DATE", e."CREATED_BY", e."MODIFIED_DATE", e."MODIFIED_BY"
    FROM "EXCEPTION" e
    WHERE e."EXCEPTION_DATE" = :exc_date
      AND e."RULE_ID" IN (
          SELECT r."RULE_ID"
          FROM "RULE" r
          JOIN "RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
          WHERE :P_RULE_NAME IS NULL
             OR :P_RULE_NAME = ''
             OR :P_RULE_NAME = 'All'
             OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                   AND rc."NAME" = :P_RULE_NAME)
             OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                   AND rg."NAME"  = :P_RULE_NAME)
      );
    affected := SQLROWCOUNT;

    DELETE FROM "EXCEPTION"
    WHERE "EXCEPTION_DATE" = :exc_date
      AND "RULE_ID" IN (
          SELECT r."RULE_ID"
          FROM "RULE" r
          JOIN "RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
          WHERE :P_RULE_NAME IS NULL
             OR :P_RULE_NAME = ''
             OR :P_RULE_NAME = 'All'
             OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                   AND rc."NAME" = :P_RULE_NAME)
             OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                   AND rg."NAME"  = :P_RULE_NAME)
      );

    RETURN affected;
END;
$$;
