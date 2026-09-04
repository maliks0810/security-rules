-- GET_EXCEPTIONS reads the slim EXCEPTION table joined with RULE and
-- the various lookup tables. Returns 23 columns matching the Exception Go
-- model 1:1 (no dummy NULL columns to fit a legacy struct). RULE has no
-- RULE_TYPE_ID / RULE_GROUP_ID yet, so p_rule_catalog / p_rule_group filters
-- are accept-all (pending future schema work).

DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text, date);
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text, date, text);

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
    p_exception_date    date DEFAULT NULL,
    -- SECURITY_GROUP filter. NULL / '' / 'All' means no filter and the
    -- original query runs untouched. Any other value selects a SEPARATE
    -- query that joins DIM_SECURITY, rather than bolting an
    -- always-evaluated predicate onto the existing list.
    p_security_group    text DEFAULT NULL
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
LANGUAGE plpgsql
AS $$
BEGIN
    -- plpgsql rather than LANGUAGE sql so the two queries are genuinely
    -- separate statements: only the branch the caller asked for is
    -- planned and run. A UNION ALL guarded by the flag would plan both.
    --
    -- The projection, the joins and every other predicate are identical
    -- in both branches; the ONLY difference is the DIM_SECURITY join.
    -- Keep them in step.
    IF p_security_group IS NULL OR p_security_group IN ('', 'All') THEN
        RETURN QUERY
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
           COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
           -- Explicit ::text cast. DM_USER."USER" is varchar and the
           -- function declares ASSIGN_TO as text; LANGUAGE sql coerced
           -- that implicitly, but plpgsql RETURN QUERY does not and
           -- fails with "structure of query does not match function
           -- result type".
           du."USER"::text                AS "ASSIGN_TO",
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
    LEFT JOIN public."DM_USER"                 du  ON du."ID" = COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
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
    ELSE
        RETURN QUERY
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
           COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
           -- Explicit ::text cast. DM_USER."USER" is varchar and the
           -- function declares ASSIGN_TO as text; LANGUAGE sql coerced
           -- that implicitly, but plpgsql RETURN QUERY does not and
           -- fails with "structure of query does not match function
           -- result type".
           du."USER"::text                AS "ASSIGN_TO",
           e."RESULT_TYPE_ID",
           ept."NAME"::text               AS "PRIORITY",
           est."NAME"::text               AS "SEVERITY",
           et."NAME"::text                AS "EXCEPTION_TYPE",
           e."CREATED_DATE",
           e."CREATED_BY"::text,
           e."MODIFIED_DATE",
           e."MODIFIED_BY"::text
    FROM public."EXCEPTION" e
    -- Inner join, so a security with no DIM_SECURITY row drops out
    -- of this branch. That is the point of the filter.
    JOIN public."DIM_SECURITY" ds ON ds."ALADDIN_ID" = e."ASSET_ID"
                                 AND ds."SECURITY_GROUP" = p_security_group
    LEFT JOIN public."RULE"                  r ON r."RULE_ID"                     = e."RULE_ID"
    LEFT JOIN public."EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"           = r."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
    LEFT JOIN public."RULE_CATALOG"            rc  ON rc."RULE_CATALOG_ID"             = r."RULE_CATALOG_ID"
    LEFT JOIN public."RULE_GROUP"              rg  ON rg."RULE_GROUP_ID"               = rc."RULE_GROUP_ID"
    LEFT JOIN public."EXCEPTION_STATE"         es    ON es."EXCEPTION_STATE_ID"          = e."STATE_ID"
    LEFT JOIN public."EXCEPTION_STATUS"        est_s ON est_s."EXCEPTION_STATUS_ID"       = e."STATUS_ID"
    LEFT JOIN public."DM_USER"                 du  ON du."ID" = COALESCE(e."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
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
    END IF;
END;
$$;
