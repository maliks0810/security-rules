-- INSERT_EXCEPTION writes one row to the slim EXCEPTION table.
-- Slimmer than INSERT_SECURITY_EXCEPTION because the target table has
-- fewer columns. EXCEPTION_ID is identity-assigned, so it's not a param.
-- COMMENT_ID and SUPPRESS_DATE are omitted (no source in the current
-- rule-execution flow). RESULT_DATA carries the JSON column-array of
-- results pulled from RULE_CATALOG_SOURCE for the firing rule.

DROP FUNCTION IF EXISTS public."INSERT_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, numeric, numeric, timestamp, text
);
DROP FUNCTION IF EXISTS public."INSERT_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, jsonb, numeric, numeric, timestamp, text
);

CREATE OR REPLACE FUNCTION public."INSERT_EXCEPTION"(
    "RULE_ID"           numeric,
    "ASSET_ID"          varchar,
    "EXCEPTION_DATE"    date,
    "ID_BB_GLOBAL"      varchar,
    "STATUS_ID"         numeric,
    "EXCEPTION_TIME"    timestamp,
    "ISSUE_DESCRIPTION" text,
    "RESULT_DATA"       jsonb,
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
        "STATUS_ID", "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE", "CREATED_BY"
    ) VALUES (
        "RULE_ID"::int, "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
        COALESCE(NULLIF("STATUS_ID"::int, 0), 1),  -- default to Pending
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "ASSIGN_TO_ID"::int, "RESULT_TYPE_ID"::int, "CREATED_DATE", "CREATED_BY"
    );
$$;
