-- GET_EXCEPTIONS reads the slim EXCEPTION table joined with RULE and
-- the various lookup tables. Returns 23 columns matching the Exception Go
-- model 1:1 (no dummy NULL columns to fit a legacy struct). RULE has no
-- RULE_TYPE_ID / RULE_GROUP_ID yet, so p_rule_catalog / p_rule_group filters
-- are accept-all (pending future schema work).

DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text, date);

CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTIONS"(
    p_asset_id          character varying DEFAULT NULL,
    p_exception_type    text DEFAULT NULL,
    p_severity          text DEFAULT NULL,
    p_priority          text DEFAULT NULL,
    p_rule_catalog         text DEFAULT NULL,
    p_rule_name         text DEFAULT NULL,
    p_rule_group        text DEFAULT NULL,
    p_exception_state   text DEFAULT NULL,
    p_assign_to         text DEFAULT NULL,
    p_rule_name_pattern text DEFAULT NULL,
    -- EXCEPTION_DATE cut-off. Required — callers must resolve
    -- "today" (or the target day) themselves and pass an explicit
    -- date. Passing NULL matches no rows.
    p_exception_date    date DEFAULT NULL
)
RETURNS TABLE(
    "EXCEPTION_ID"      bigint,
    "RULE_ID"           integer,
    "RULE_NAME"         text,
    "ASSET_ID"          character varying,
    "EXCEPTION_DATE"    date,
    "EXCEPTION_TIME"    timestamp without time zone,
    "ID_BB_GLOBAL"      character varying,
    "STATE_ID"          integer,
    "EXCEPTION_STATE"   text,
    "STATUS_ID"         integer,
    "EXCEPTION_STATUS"  text,
    "COMMENTS"          text,
    "ISSUE_DESCRIPTION" text,
    "RESULT_DATA"       text,
    "SUPPRESS_DATE"     date,
    "OPEN_DATE"         date,
    "CLOSE_DATE"        date,
    "ASSIGN_TO_ID"      integer,
    "ASSIGN_TO"         text,
    "RESULT_TYPE_ID"    integer,
    "PRIORITY"          text,
    "SEVERITY"          text,
    "EXCEPTION_TYPE"    text,
    "CREATED_DATE"      timestamp without time zone,
    "CREATED_BY"        text,
    "MODIFIED_DATE"     timestamp without time zone,
    "MODIFIED_BY"       text
)
LANGUAGE sql
AS $$
    SELECT e."EXCEPTION_ID",
           e."RULE_ID",
           r."RULE_NAME"::text,
           e."ASSET_ID",
           e."EXCEPTION_DATE",
           e."EXCEPTION_TIME",
           e."ID_BB_GLOBAL",
           e."STATE_ID",
           es."NAME"::text                AS "EXCEPTION_STATE",
           e."STATUS_ID",
           est_s."NAME"::text             AS "EXCEPTION_STATUS",
           e."COMMENTS"::text,
           e."ISSUE_DESCRIPTION"::text,
           e."RESULT_DATA"::text,
           e."SUPPRESS_DATE",
           e."OPEN_DATE",
           e."CLOSE_DATE",
           COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
           du."USER"                      AS "ASSIGN_TO",
           e."RESULT_TYPE_ID",
           ept."NAME"::text               AS "PRIORITY",
           est."NAME"::text               AS "SEVERITY",
           et."NAME"::text                AS "EXCEPTION_TYPE",
           e."CREATED_DATE",
           e."CREATED_BY"::text,
           e."MODIFIED_DATE",
           e."MODIFIED_BY"::text
    FROM public."EXCEPTION" e
    LEFT JOIN public."RULE"                  r ON r."RULE_ID"                     = e."RULE_ID"
    LEFT JOIN public."EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"           = r."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN public."RULE_CATALOG"            rc  ON rc."RULE_CATALOG_ID"             = r."RULE_CATALOG_ID"
    LEFT JOIN public."RULE_GROUP"              rg  ON rg."RULE_GROUP_ID"               = rc."RULE_GROUP_ID"
    LEFT JOIN public."EXCEPTION_STATE"         es    ON es."EXCEPTION_STATE_ID"          = e."STATE_ID"
    LEFT JOIN public."EXCEPTION_STATUS"        est_s ON est_s."EXCEPTION_STATUS_ID"       = e."STATUS_ID"
    -- Latest RULE_ASSIGN_OVERRIDE row per RULE_ID (written by Bulk
    -- Assign). Precedence: per-row EXCEPTION.ASSIGN_TO_ID > bulk
    -- override > RULE default. This lets subsequent-run exceptions
    -- inherit the new assignee before any per-row grid edit.
    LEFT JOIN (
        SELECT DISTINCT ON ("RULE_ID") "RULE_ID", "ASSIGN_TO_ID"
        FROM public."RULE_ASSIGN_OVERRIDE"
        ORDER BY "RULE_ID",
                 "CREATED_DATE" DESC,
                 "RULE_ASSIGN_OVERRIDE_ID" DESC
    ) rao ON rao."RULE_ID" = r."RULE_ID"
    LEFT JOIN public."DM_USER"                 du  ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
    WHERE e."EXCEPTION_DATE" = p_exception_date
      AND (p_asset_id          IS NULL OR e."ASSET_ID"  = p_asset_id)
      AND (p_exception_type    IS NULL OR et."NAME"     = p_exception_type)
      AND (p_severity          IS NULL OR est."NAME"    = p_severity)
      AND (p_priority          IS NULL OR ept."NAME"    = p_priority)
      AND (p_rule_catalog      IS NULL OR p_rule_catalog = 'All' OR rc."NAME" = p_rule_catalog)
      AND (p_rule_name         IS NULL OR p_rule_name  = 'All' OR r."RULE_NAME" = p_rule_name)
      AND (p_rule_group        IS NULL OR p_rule_group = 'All' OR rg."NAME" = p_rule_group)
      AND (p_exception_state   IS NULL OR p_exception_state = 'All' OR es."NAME" = p_exception_state)
      AND (p_assign_to         IS NULL OR p_assign_to  = 'All' OR du."USER" = p_assign_to)
      AND (p_rule_name_pattern IS NULL OR r."RULE_NAME" ILIKE p_rule_name_pattern);
$$;
