-- UPDATE_EXCEPTION updates the EXCEPTION row identified by (ASSET_ID, RULE_ID).
-- Mirrors INSERT_EXCEPTION's param list (slim EXCEPTION schema).
-- STATE_ID is force-reset to 1 (Pending) on every update because the
-- assumption is the rule fired again and we want the exception re-opened.
-- ID_BB_GLOBAL, ASSIGN_TO_ID, and RESULT_DATA use COALESCE so a NULL input
-- keeps the existing value (matches UPDATE_SECURITY_EXCEPTION's pattern).

DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, numeric, numeric, timestamp, text
);
DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, jsonb, numeric, numeric, timestamp, text
);
DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, json, numeric, numeric, timestamp, text
);
DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION"(
    numeric, varchar, date, varchar, numeric,
    timestamp, text, json, numeric, numeric, timestamp, text, numeric
);

CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION"(
    p_rule_id           numeric,
    p_asset_id          varchar,
    p_exception_date    date,
    p_id_bb_global      varchar,
    p_state_id          numeric,
    p_exception_time    timestamp,
    p_issue_description text,
    p_result_data       json,
    p_assign_to_id      numeric,
    p_result_type_id    numeric,
    p_created_date      timestamp,
    p_created_by        text,
    p_status_id         numeric DEFAULT NULL
)
RETURNS void
LANGUAGE sql
AS $$
    UPDATE public."EXCEPTION"
       SET "EXCEPTION_DATE"    = p_exception_date,
           "EXCEPTION_TIME"    = p_exception_time,
           "STATE_ID"          = 1,  -- re-flagged â†’ Pending
           "ISSUE_DESCRIPTION" = p_issue_description,
           "RESULT_DATA"       = COALESCE(p_result_data, "RESULT_DATA"),
           "ASSIGN_TO_ID"      = COALESCE(p_assign_to_id::int, "ASSIGN_TO_ID"),
           "RESULT_TYPE_ID"    = p_result_type_id::int,
           "CREATED_DATE"      = p_created_date,
           "CREATED_BY"        = p_created_by,
           "ID_BB_GLOBAL"      = COALESCE(p_id_bb_global, "ID_BB_GLOBAL"),
           "STATUS_ID"         = COALESCE(p_status_id::int, "STATUS_ID"),
           -- OPEN_DATE is write-once: it records the day the exception
           -- was FIRST surfaced, so an existing value is never
           -- overwritten. Today is stamped only when the row's new
           -- STATUS_ID is 1 (New) and there is nothing there yet.
           "OPEN_DATE"         = COALESCE(
                                     "OPEN_DATE",
                                     CASE
                                         WHEN COALESCE(p_status_id::int, "STATUS_ID") = 1
                                             THEN (NOW() AT TIME ZONE 'UTC')::date
                                     END
                                 )
     WHERE "ASSET_ID" = p_asset_id
       AND "RULE_ID"  = p_rule_id::int;
$$;
