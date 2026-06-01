CREATE OR REPLACE PROCEDURE UPDATE_SECURITY_EXCEPTION(
    P_SECURITY_EXCEPTION_ID NUMBER,
    P_RULE_ID               NUMBER,
    P_RUN_DATE              TIMESTAMP_NTZ,
    P_RUN_START             TIMESTAMP_NTZ,
    P_RUN_END               TIMESTAMP_NTZ,
    P_RESULT_TYPE_ID        NUMBER,
    P_EXCEPTION_STATUS_ID   NUMBER,
    P_SEVERITY_TYPE_ID      NUMBER,
    P_PROCESS_TYPE_ID       NUMBER,
    P_CATEGORY_TYPE_ID      NUMBER,
    P_ASSIGN_TO_ID          NUMBER,
    P_ASSIGN_TO_DATE        VARCHAR,
    P_RESOLVE_DATE          VARCHAR,
    P_BUS_TERM_SOURCE_ID    NUMBER,
    P_ISSUE_DESCRIPTION     VARCHAR,
    P_SOURCE_SYSTEM_CODE    VARCHAR,
    P_CREATED_DATE          TIMESTAMP_NTZ,
    P_CREATED_BY            VARCHAR,
    P_MODIFIED_BY           VARCHAR,
    P_MODIFIED_DATE         TIMESTAMP_NTZ,
    P_EXCEPTION_SOURCE_ID   NUMBER,
    P_EXCEPTION_TYPE_ID     NUMBER,
    P_DQM_APP_ID            NUMBER,
    P_ASSET_TYPE_ID         NUMBER,
    P_ASSET                 VARCHAR,
    P_CUSIP_TYPE_CODE       VARCHAR,
    P_ASSIGNED_BY           VARCHAR,
    P_COMMENTS              VARCHAR,
    P_ASSET_ID              VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    UPDATE "SECURITY_EXCEPTION"
       SET "RUN_DATE"            = :P_RUN_DATE,
           "RUN_START"           = :P_RUN_START,
           "RUN_END"             = :P_RUN_END,
           "RESULT_TYPE_ID"      = :P_RESULT_TYPE_ID,
           "EXCEPTION_STATUS_ID" = 1,                            -- re-flagged → Pending
           "SEVERITY_TYPE_ID"    = :P_SEVERITY_TYPE_ID,
           "PROCESS_TYPE_ID"     = :P_PROCESS_TYPE_ID,
           "CATEGORY_TYPE_ID"    = :P_CATEGORY_TYPE_ID,
           "ASSIGN_TO_ID"        = COALESCE(:P_ASSIGN_TO_ID,   "ASSIGN_TO_ID"),
           "ASSIGN_TO_DATE"      = COALESCE(:P_ASSIGN_TO_DATE, "ASSIGN_TO_DATE"),
           "RESOLVE_DATE"        = :P_RESOLVE_DATE,
           "BUS_TERM_SOURCE_ID"  = :P_BUS_TERM_SOURCE_ID,
           "ISSUE_DESCRIPTION"   = :P_ISSUE_DESCRIPTION,
           "SOURCE_SYSTEM_CODE"  = :P_SOURCE_SYSTEM_CODE,
           "CREATED_DATE"        = :P_CREATED_DATE,
           "CREATED_BY"          = :P_CREATED_BY,
           "MODIFIED_BY"         = :P_MODIFIED_BY,
           "MODIFIED_DATE"       = :P_MODIFIED_DATE,
           "EXCEPTION_SOURCE_ID" = :P_EXCEPTION_SOURCE_ID,
           "EXCEPTION_TYPE_ID"   = :P_EXCEPTION_TYPE_ID,
           "DQM_APP_ID"          = :P_DQM_APP_ID,
           "ASSET_TYPE_ID"       = :P_ASSET_TYPE_ID,
           "ASSET"               = :P_ASSET,
           "CUSIP_TYPE_CODE"     = :P_CUSIP_TYPE_CODE,
           "ASSIGNED_BY"         = COALESCE(:P_ASSIGNED_BY, "ASSIGNED_BY"),
           "COMMENTS"            = :P_COMMENTS
     WHERE "ASSET_ID" = :P_ASSET_ID
       AND "RULE_ID" = :P_RULE_ID;
    RETURN 'OK';
END;
$$;
