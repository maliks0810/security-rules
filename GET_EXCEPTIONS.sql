CREATE OR REPLACE PROCEDURE GET_EXCEPTIONS(
    P_ASSET_ID         VARCHAR DEFAULT NULL,
    P_EXCEPTION_TYPE   VARCHAR DEFAULT NULL,
    P_SEVERITY         VARCHAR DEFAULT NULL,
    P_PRIORITY         VARCHAR DEFAULT NULL,
    P_RULE_TYPE        VARCHAR DEFAULT NULL,
    P_RULE_NAME        VARCHAR DEFAULT NULL,
    P_RULE_GROUP       VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATUS VARCHAR DEFAULT NULL,
    P_ASSIGN_TO        VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "SECURITY_EXCEPTION_ID" NUMBER,
    "RULE_ID"               NUMBER,
    "RULE_NAME"             VARCHAR,
    "PRIORITY"              VARCHAR,
    "ASSET_ID"              VARCHAR,
    "RUN_DATE"              TIMESTAMP_NTZ,
    "RUN_START"             TIMESTAMP_NTZ,
    "RESULT_TYPE_ID"        NUMBER,
    "EXCEPTION_SOURCE_ID"   NUMBER,
    "EXCEPTION_STATUS_ID"   NUMBER,
    "SEVERITY_TYPE_ID"      NUMBER,
    "PROCESS_TYPE_ID"       NUMBER,
    "CATEGORY_TYPE_ID"      NUMBER,
    "ASSIGN_TO"             VARCHAR,
    "ASSIGNED_BY"           VARCHAR,
    "ISSUE_DESCRIPTION"     VARCHAR,
    "CREATED_DATE"          TIMESTAMP_NTZ,
    "CREATED_BY"            VARCHAR,
    "MODIFIED_DATE"         TIMESTAMP_NTZ,
    "MODIFIED_BY"           VARCHAR,
    "EXCEPTION_STATUS"      VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT
            se."SECURITY_EXCEPTION_ID",
            se."RULE_ID",
            r."RULE_NAME",
            st."CODE"               AS "PRIORITY",
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
            es."CODE"           AS "EXCEPTION_STATUS"
        FROM "SECURITY_EXCEPTION" se
        JOIN "SEVERITY_TYPE" st ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
        JOIN "RULE"          r  ON r."RULE_ID"          = se."RULE_ID"
        LEFT JOIN "RULE_TYPE"        rt ON rt."RULE_TYPE_ID"        = r."RULE_TYPE_ID"
        LEFT JOIN "RULE_GROUP"       rg ON rg."RULE_GROUP_ID"       = rt."RULE_GROUP_ID"
        LEFT JOIN "EXCEPTION_TYPE"   et ON et."EXCEPTION_TYPE_ID"   = se."EXCEPTION_TYPE_ID"
        LEFT JOIN "CATEGORY_TYPE"    ct ON ct."CATEGORY_TYPE_ID"    = se."CATEGORY_TYPE_ID"
        LEFT JOIN "EXCEPTION_STATUS" es ON es."EXCEPTION_STATUS_ID" = se."EXCEPTION_STATUS_ID"
        LEFT JOIN "DM_USER"          du ON du."ID"                  = se."ASSIGN_TO_ID"
        WHERE (:P_ASSET_ID         IS NULL OR se."ASSET_ID"  = :P_ASSET_ID)
          AND (:P_EXCEPTION_TYPE   IS NULL OR et."CODE"      = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY         IS NULL OR ct."CODE"      = :P_SEVERITY)
          AND (:P_PRIORITY         IS NULL OR st."CODE"      = :P_PRIORITY)
          AND (:P_RULE_TYPE        IS NULL OR :P_RULE_TYPE        = 'All' OR rt."NAME"     = :P_RULE_TYPE)
          AND (:P_RULE_NAME        IS NULL OR :P_RULE_NAME        = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_RULE_GROUP       IS NULL OR :P_RULE_GROUP       = 'All' OR rg."NAME"     = :P_RULE_GROUP)
          AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es."CODE"     = :P_EXCEPTION_STATUS)
          AND (:P_ASSIGN_TO        IS NULL OR :P_ASSIGN_TO        = 'All' OR du."USER"     = :P_ASSIGN_TO)
    );
    RETURN TABLE(res);
END;
$$;
