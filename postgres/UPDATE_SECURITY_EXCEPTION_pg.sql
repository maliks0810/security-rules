-- UPDATE_SECURITY_EXCEPTION now accepts ID_BB_GLOBAL (Bloomberg global id)
-- as the last parameter. SECURITY_EXCEPTION."ID_BB_GLOBAL" is varchar(15).

DROP FUNCTION IF EXISTS public."UPDATE_SECURITY_EXCEPTION"(
    numeric, numeric,
    timestamp, timestamp, timestamp,
    numeric, numeric, numeric, numeric, numeric,
    numeric, text, text, numeric, text, text,
    timestamp, text, text, timestamp,
    numeric, numeric, numeric, numeric, text, text, text, text,
    varchar
);

CREATE OR REPLACE FUNCTION public."UPDATE_SECURITY_EXCEPTION"(
    p_security_exception_id numeric,
    p_rule_id               numeric,
    p_run_date              timestamp,
    p_run_start             timestamp,
    p_run_end               timestamp,
    p_result_type_id        numeric,
    p_exception_status_id   numeric,
    p_severity_type_id      numeric,
    p_process_type_id       numeric,
    p_category_type_id      numeric,
    p_assign_to_id          numeric,
    p_assign_to_date        text,
    p_resolve_date          text,
    p_bus_term_source_id    numeric,
    p_issue_description     text,
    p_source_system_code    text,
    p_created_date          timestamp,
    p_created_by            text,
    p_modified_by           text,
    p_modified_date         timestamp,
    p_exception_source_id   numeric,
    p_exception_type_id     numeric,
    p_dqm_app_id            numeric,
    p_asset_type_id         numeric,
    p_asset                 text,
    p_cusip_type_code       text,
    p_assigned_by           text,
    p_comments              text,
    p_asset_id              varchar,
    p_id_bb_global          varchar
)
RETURNS void
LANGUAGE sql
AS $$
    UPDATE public."SECURITY_EXCEPTION"
       SET "RUN_DATE"            = p_run_date,
           "RUN_START"           = p_run_start,
           "RUN_END"             = p_run_end,
           "RESULT_TYPE_ID"      = p_result_type_id,
           "EXCEPTION_STATUS_ID" = 1,  -- re-flagged → Pending
           "SEVERITY_TYPE_ID"    = p_severity_type_id,
           "PROCESS_TYPE_ID"     = p_process_type_id,
           "CATEGORY_TYPE_ID"    = p_category_type_id,
           "ASSIGN_TO_ID"        = COALESCE(p_assign_to_id, "ASSIGN_TO_ID"),
           "ASSIGN_TO_DATE"      = COALESCE(p_assign_to_date, "ASSIGN_TO_DATE"),
           "RESOLVE_DATE"        = p_resolve_date,
           "BUS_TERM_SOURCE_ID"  = p_bus_term_source_id,
           "ISSUE_DESCRIPTION"   = p_issue_description,
           "SOURCE_SYSTEM_CODE"  = p_source_system_code,
           "CREATED_DATE"        = p_created_date,
           "CREATED_BY"          = p_created_by,
           "MODIFIED_BY"         = p_modified_by,
           "MODIFIED_DATE"       = p_modified_date,
           "EXCEPTION_SOURCE_ID" = p_exception_source_id,
           "EXCEPTION_TYPE_ID"   = p_exception_type_id,
           "DQM_APP_ID"          = p_dqm_app_id,
           "ASSET_TYPE_ID"       = p_asset_type_id,
           "ASSET"               = p_asset,
           "CUSIP_TYPE_CODE"     = p_cusip_type_code,
           "ASSIGNED_BY"         = COALESCE(p_assigned_by, "ASSIGNED_BY"),
           "COMMENTS"            = p_comments,
           "ID_BB_GLOBAL"        = COALESCE(p_id_bb_global, "ID_BB_GLOBAL")
     WHERE "ASSET_ID" = p_asset_id
       AND "RULE_ID"  = p_rule_id;
$$;
