DROP FUNCTION IF EXISTS public."GET_EXCEPTIONS"(varchar);
DROP FUNCTION IF EXISTS public."GET_EXCEPTIONS"(varchar, text);
DROP FUNCTION IF EXISTS public."GET_EXCEPTIONS"(varchar, text, text);
DROP FUNCTION IF EXISTS public."GET_EXCEPTIONS"(varchar, text, text, text);

CREATE OR REPLACE FUNCTION public."GET_EXCEPTIONS"(
    p_asset_id       character varying,
    p_exception_type text DEFAULT NULL,
    p_severity       text DEFAULT NULL,
    p_priority       text DEFAULT NULL
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
    "MODIFIED_BY"           text
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
           se."ASSIGN_TO",
           se."ASSIGNED_BY",
           se."ISSUE_DESCRIPTION",
           se."CREATED_DATE",
           se."CREATED_BY",
           se."MODIFIED_DATE",
           se."MODIFIED_BY"
    FROM public."SECURITY_EXCEPTION" se
    JOIN public."SEVERITY_TYPE" st
      ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
    JOIN public."RULE" r
      ON r."RULE_ID" = se."RULE_ID"
    LEFT JOIN public."EXCEPTION_TYPE" et
      ON et."EXCEPTION_TYPE_ID" = se."EXCEPTION_TYPE_ID"
    LEFT JOIN public."CATEGORY_TYPE" ct
      ON ct."CATEGORY_TYPE_ID" = se."CATEGORY_TYPE_ID"
    WHERE se."ASSET_ID" = p_asset_id
      AND (p_exception_type IS NULL OR et."CODE" = p_exception_type)
      AND (p_severity       IS NULL OR ct."CODE" = p_severity)
      AND (p_priority       IS NULL OR st."CODE" = p_priority);
$$;
