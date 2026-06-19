-- INSERT_EXCEPTION writes one row to the slim EXCEPTION table.
-- Slimmer than INSERT_SECURITY_EXCEPTION because the target table has
-- fewer columns. EXCEPTION_ID is identity-assigned, so it's not a param.
-- COMMENT_ID, SUPPRESS_DATE, RESULT_DATA are also omitted (no source
-- in the current rule-execution flow).

DROP FUNCTION IF EXISTS public."INSERT_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, numeric, numeric, timestamp, text
);

CREATE OR REPLACE FUNCTION public."INSERT_EXCEPTION"(
    "RULE_ID"           numeric,
    "ASSET_ID"          varchar,
    "EXCEPTION_DATE"    date,
    "ID_BB_GLOBAL"      varchar,
    "STATUS_ID"         numeric,
    "EXCEPTION_TIME"    timestamp,
    "ISSUE_DESCRIPTION" text,
    "ASSIGN_TO_ID"      numeric,
    "RESULT_TYPE_ID"    numeric,
    "CREATED_DATE"      timestamp,
    "CREATED_BY"        text
)
RETURNS void
LANGUAGE sql
AS $$
    INSERT INTO public."EXCEPTION" (
        "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
        "STATUS_ID", "EXCEPTION_TIME", "ISSUE_DESCRIPTION",
        "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE", "CREATED_BY"
    ) VALUES (
        "RULE_ID"::int, "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
        COALESCE(NULLIF("STATUS_ID"::int, 0), 1),  -- default to Pending
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION",
        "ASSIGN_TO_ID"::int, "RESULT_TYPE_ID"::int, "CREATED_DATE", "CREATED_BY"
    );
$$;
