-- INSERT_SECURITY_EXCEPTION now accepts ID_BB_GLOBAL (Bloomberg global id)
-- as the last parameter. SECURITY_EXCEPTION."ID_BB_GLOBAL" is varchar(15).

DROP FUNCTION IF EXISTS public."INSERT_SECURITY_EXCEPTION"(
    numeric,
    timestamp, timestamp, timestamp,
    numeric, numeric, numeric, numeric, numeric,
    numeric, text, text, numeric, text, text,
    timestamp, text, text, timestamp,
    numeric, numeric, numeric, numeric, text, text, text, text,
    varchar
);

CREATE OR REPLACE FUNCTION public."INSERT_SECURITY_EXCEPTION"(
    "RULE_ID"               numeric,
    "RUN_DATE"              timestamp,
    "RUN_START"             timestamp,
    "RUN_END"               timestamp,
    "RESULT_TYPE_ID"        numeric,
    "EXCEPTION_STATUS_ID"   numeric,
    "SEVERITY_TYPE_ID"      numeric,
    "PROCESS_TYPE_ID"       numeric,
    "CATEGORY_TYPE_ID"      numeric,
    "ASSIGN_TO_ID"          numeric,
    "ASSIGN_TO_DATE"        text,
    "RESOLVE_DATE"          text,
    "BUS_TERM_SOURCE_ID"    numeric,
    "ISSUE_DESCRIPTION"     text,
    "SOURCE_SYSTEM_CODE"    text,
    "CREATED_DATE"          timestamp,
    "CREATED_BY"            text,
    "MODIFIED_BY"           text,
    "MODIFIED_DATE"         timestamp,
    "EXCEPTION_SOURCE_ID"   numeric,
    "EXCEPTION_TYPE_ID"     numeric,
    "DQM_APP_ID"            numeric,
    "ASSET_TYPE_ID"         numeric,
    "ASSET"                 text,
    "CUSIP_TYPE_CODE"       text,
    "ASSIGNED_BY"           text,
    "COMMENTS"              text,
    "ASSET_ID"              varchar(30),
    "ID_BB_GLOBAL"          varchar(15)
)
RETURNS void
LANGUAGE sql
AS $$
    INSERT INTO public."SECURITY_EXCEPTION" (
        "RULE_ID", "RUN_DATE", "RUN_START", "RUN_END",
        "RESULT_TYPE_ID", "EXCEPTION_STATUS_ID", "SEVERITY_TYPE_ID", "PROCESS_TYPE_ID",
        "CATEGORY_TYPE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_DATE", "RESOLVE_DATE",
        "BUS_TERM_SOURCE_ID", "ISSUE_DESCRIPTION", "SOURCE_SYSTEM_CODE",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_BY", "MODIFIED_DATE",
        "EXCEPTION_SOURCE_ID", "EXCEPTION_TYPE_ID", "DQM_APP_ID", "ASSET_TYPE_ID",
        "ASSET", "CUSIP_TYPE_CODE", "ASSIGNED_BY", "COMMENTS", "ASSET_ID",
        "ID_BB_GLOBAL"
    ) VALUES (
        "RULE_ID", "RUN_DATE", "RUN_START", "RUN_END",
        "RESULT_TYPE_ID",
        COALESCE(NULLIF("EXCEPTION_STATUS_ID", 0), 1),  -- default to Pending
        "SEVERITY_TYPE_ID", "PROCESS_TYPE_ID",
        "CATEGORY_TYPE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_DATE", "RESOLVE_DATE",
        "BUS_TERM_SOURCE_ID", "ISSUE_DESCRIPTION", "SOURCE_SYSTEM_CODE",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_BY", "MODIFIED_DATE",
        "EXCEPTION_SOURCE_ID", "EXCEPTION_TYPE_ID", "DQM_APP_ID", "ASSET_TYPE_ID",
        "ASSET", "CUSIP_TYPE_CODE", "ASSIGNED_BY", "COMMENTS", "ASSET_ID",
        "ID_BB_GLOBAL"
    );
$$;
