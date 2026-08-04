DROP FUNCTION IF EXISTS public."SP_ARCHIVE_EXCEPTIONS"(text, text);
DROP FUNCTION IF EXISTS public."SP_DELETE_EXCEPTIONS"(text, text);

-- Moves today's EXCEPTION rows in scope into EXCEPTION_HIST (stamping a
-- per-date BATCH_ID) instead of deleting them outright. Scope semantics
-- match SP_GET_RULES / the retired SP_DELETE_EXCEPTIONS:
--   p_rule_type = 'CATALOG' or 'RULE'  → p_rule_name = RULE_CATALOG.NAME
--   p_rule_type = 'GROUP'              → p_rule_name = RULE_GROUP.NAME
--   p_rule_name NULL / empty / 'All'   → every catalog (full archive of today)
--
-- BATCH_ID is per EXCEPTION_DATE. First run of a day starts at 1;
-- subsequent same-day runs increment (MAX + 1). A new day starts over
-- at 1 because MAX() over that date returns NULL.
--
-- Returns the number of rows moved.
CREATE OR REPLACE FUNCTION public."SP_ARCHIVE_EXCEPTIONS"(
    p_rule_name text DEFAULT NULL,
    p_rule_type text DEFAULT NULL
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    exc_date   date   := (NOW() AT TIME ZONE 'UTC')::date;
    next_batch bigint;
    affected   integer := 0;
BEGIN
    SELECT COALESCE(MAX("BATCH_ID"), 0) + 1
      INTO next_batch
      FROM public."EXCEPTION_HIST"
     WHERE "EXCEPTION_DATE" = exc_date;

    -- Single WITH statement: the DELETE returns each moved row, and the
    -- data-modifying `archived` CTE inserts them into EXCEPTION_HIST
    -- with the computed batch id. Data-modifying CTEs run to completion
    -- even without a top-level reference, so this is atomic in one
    -- statement.
    WITH moved AS (
        DELETE FROM public."EXCEPTION"
        WHERE "EXCEPTION_DATE" = exc_date
          AND "RULE_ID" IN (
              SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN public."RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
              WHERE p_rule_name IS NULL
                 OR p_rule_name = ''
                 OR p_rule_name = 'All'
                 OR (UPPER(COALESCE(p_rule_type, 'CATALOG')) IN ('CATALOG','RULE')
                       AND rc."NAME" = p_rule_name)
                 OR (UPPER(p_rule_type) = 'GROUP'
                       AND rg."NAME"  = p_rule_name)
          )
        RETURNING *
    ),
    archived AS (
        INSERT INTO public."EXCEPTION_HIST" (
            "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
            "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
            "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
            "SUPPRESS_DATE", "OPEN_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
            "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        )
        SELECT
            "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", next_batch,
            "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
            "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
            "SUPPRESS_DATE", "OPEN_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
            "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        FROM moved
        RETURNING 1
    )
    SELECT COUNT(*) INTO affected FROM moved;

    RETURN affected;
END;
$$;
