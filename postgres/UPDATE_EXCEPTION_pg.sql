-- UPDATE_EXCEPTION updates the EXCEPTION row identified by (ASSET_ID, RULE_ID).
-- Mirrors INSERT_EXCEPTION's param list (slim EXCEPTION schema).
-- STATUS_ID is force-reset to 1 (Pending) on every update because the
-- assumption is the rule fired again and we want the exception re-opened.
-- ID_BB_GLOBAL, ASSIGN_TO_ID, and RESULT_DATA use COALESCE so a NULL input
-- keeps the existing value (matches UPDATE_SECURITY_EXCEPTION's pattern).

DROP FUNCTION IF EXISTS public."UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, numeric, numeric, timestamp, text
);
DROP FUNCTION IF EXISTS public."UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, jsonb, numeric, numeric, timestamp, text
);

CREATE OR REPLACE FUNCTION public."UPDATE_EXCEPTION"(
    p_rule_id           numeric,
    p_asset_id          varchar,
    p_exception_date    date,
    p_id_bb_global      varchar,
    p_status_id         numeric,
    p_exception_time    timestamp,
    p_issue_description text,
    p_result_data       jsonb,
    p_assign_to_id      numeric,
    p_result_type_id    numeric,
    p_created_date      timestamp,
    p_created_by        text
)
RETURNS void
LANGUAGE sql
AS $$
    UPDATE public."EXCEPTION"
       SET "EXCEPTION_DATE"    = p_exception_date,
           "EXCEPTION_TIME"    = p_exception_time,
           "STATUS_ID"         = 1,  -- re-flagged → Pending
           "ISSUE_DESCRIPTION" = p_issue_description,
           "RESULT_DATA"       = COALESCE(p_result_data, "RESULT_DATA"),
           "ASSIGN_TO_ID"      = COALESCE(p_assign_to_id::int, "ASSIGN_TO_ID"),
           "RESULT_TYPE_ID"    = p_result_type_id::int,
           "CREATED_DATE"      = p_created_date,
           "CREATED_BY"        = p_created_by,
           "ID_BB_GLOBAL"      = COALESCE(p_id_bb_global, "ID_BB_GLOBAL")
     WHERE "ASSET_ID" = p_asset_id
       AND "RULE_ID"  = p_rule_id::int;
$$;
