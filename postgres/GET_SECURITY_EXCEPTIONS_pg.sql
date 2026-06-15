DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text, text, text, text, text);

DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text);

DROP FUNCTION IF EXISTS public."GET_SECURITY_EXCEPTIONS"(varchar, text, text, text, text, text, text, text, text, text);

CREATE OR REPLACE FUNCTION public."GET_SECURITY_EXCEPTIONS"(
    p_asset_id          character varying DEFAULT NULL,
    p_exception_type    text DEFAULT NULL,
    p_severity          text DEFAULT NULL,
    p_priority          text DEFAULT NULL,
    p_rule_catalog         text DEFAULT NULL,
    p_rule_name         text DEFAULT NULL,
    p_rule_group        text DEFAULT NULL,
    p_exception_status  text DEFAULT NULL,
    p_assign_to         text DEFAULT NULL,
    p_rule_name_pattern text DEFAULT NULL
)
RETURNS TABLE(
    "SECURITY_EXCEPTION_ID" numeric,
    "RULE_ID"               numeric,
    "RULE_NAME"             character,
    "PRIORITY"              character varying,
    "ASSET_ID"              character varying,
    "RUN_DATE"              timestamp without time zone,
    "RUN_START"             timestamp without time zone,
    "RESULT_TYPE_ID"        numeric,
    "EXCEPTION_SOURCE_ID"   numeric,
    "EXCEPTION_STATUS_ID"   numeric,
    "SEVERITY_TYPE_ID"      numeric,
    "PROCESS_TYPE_ID"       numeric,
    "CATEGORY_TYPE_ID"      numeric,
    "ASSIGN_TO"             text,
    "ASSIGNED_BY"           text,
    "ISSUE_DESCRIPTION"     text,
    "CREATED_DATE"          timestamp without time zone,
    "CREATED_BY"            text,
    "MODIFIED_DATE"         timestamp without time zone,
    "MODIFIED_BY"           text,
    "EXCEPTION_STATUS"      text
)
LANGUAGE sql
AS $$
    SELECT se."SECURITY_EXCEPTION_ID",
           se."RULE_ID",
           r."RULE_NAME",
           st."CODE"           AS "PRIORITY",
           se."ASSET_ID",
           se."RUN_DATE",
           se."RUN_START",
           se."RESULT_TYPE_ID",
           se."EXCEPTION_SOURCE_ID",
           se."EXCEPTION_STATUS_ID",
           se."SEVERITY_TYPE_ID",
           se."PROCESS_TYPE_ID",
           se."CATEGORY_TYPE_ID",
           du."USER"           AS "ASSIGN_TO",
           se."ASSIGNED_BY",
           se."ISSUE_DESCRIPTION",
           se."CREATED_DATE",
           se."CREATED_BY",
           se."MODIFIED_DATE",
           se."MODIFIED_BY",
           es."NAME"           AS "EXCEPTION_STATUS"
    FROM public."SECURITY_EXCEPTION" se
    JOIN public."SEVERITY_TYPE" st
      ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
    JOIN public."RULE" r
      ON r."RULE_ID" = se."RULE_ID"
    LEFT JOIN public."RULE_CATALOG" rc
      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
    LEFT JOIN public."RULE_GROUP" rg
      ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
    LEFT JOIN public."EXCEPTION_TYPE" et
      ON et."EXCEPTION_TYPE_ID" = se."EXCEPTION_TYPE_ID"
    LEFT JOIN public."CATEGORY_TYPE" ct
      ON ct."CATEGORY_TYPE_ID" = se."CATEGORY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_STATUS" es
      ON es."EXCEPTION_STATUS_ID" = se."EXCEPTION_STATUS_ID"
    LEFT JOIN public."DM_USER" du
      ON du."ID" = se."ASSIGN_TO_ID"
    WHERE (p_asset_id         IS NULL OR se."ASSET_ID"  = p_asset_id)
      AND (p_exception_type   IS NULL OR et."NAME"      = p_exception_type)
      AND (p_severity         IS NULL OR ct."CODE"      = p_severity)
      AND (p_priority         IS NULL OR st."CODE"      = p_priority)
      AND (p_rule_catalog        IS NULL OR p_rule_catalog        = 'All' OR rc."NAME"      = p_rule_catalog)
      AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r."RULE_NAME"  = p_rule_name)
      AND (p_rule_group       IS NULL OR p_rule_group       = 'All' OR rg."NAME"      = p_rule_group)
      AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es."NAME"      = p_exception_status)
      AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du."USER"      = p_assign_to)
      AND (p_rule_name_pattern IS NULL OR r."RULE_NAME"      ILIKE p_rule_name_pattern);
$$;
