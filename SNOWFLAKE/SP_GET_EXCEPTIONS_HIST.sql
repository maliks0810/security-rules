-- SP_GET_EXCEPTIONS_HIST reads EXCEPTION_HIST for a specific EXCEPTION_DATE
-- and returns the rows that belong to the LATEST BATCH_ID that day within
-- the caller's rule/catalog/group scope. Column shape mirrors
-- SP_GET_EXCEPTIONS exactly so callers can reuse the same scan/parse.

CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTIONS_HIST(
    P_EXCEPTION_DATE    DATE,
    P_ASSET_ID          VARCHAR DEFAULT NULL,
    P_EXCEPTION_TYPE    VARCHAR DEFAULT NULL,
    P_SEVERITY          VARCHAR DEFAULT NULL,
    P_PRIORITY          VARCHAR DEFAULT NULL,
    P_RULE_CATALOG      VARCHAR DEFAULT NULL,
    P_RULE_NAME         VARCHAR DEFAULT NULL,
    P_RULE_GROUP        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE   VARCHAR DEFAULT NULL,
    P_ASSIGN_TO         VARCHAR DEFAULT NULL,
    P_RULE_NAME_PATTERN VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "EXCEPTION_ID"      NUMBER,
    "RULE_ID"           NUMBER,
    "RULE_NAME"         VARCHAR,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATE_ID"          NUMBER,
    "EXCEPTION_STATE"   VARCHAR,
    "STATUS_ID"         NUMBER,
    "EXCEPTION_STATUS"  VARCHAR,
    "COMMENTS"          VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       VARCHAR,
    "SUPPRESS_DATE"     DATE,
    "ASSIGN_TO_ID"      NUMBER,
    "ASSIGN_TO"         VARCHAR,
    "RESULT_TYPE_ID"    NUMBER,
    "PRIORITY"          VARCHAR,
    "SEVERITY"          VARCHAR,
    "EXCEPTION_TYPE"    VARCHAR,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR,
    "MODIFIED_DATE"     TIMESTAMP_NTZ,
    "MODIFIED_BY"       VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH max_batch AS (
            SELECT MAX(h."BATCH_ID") AS mb
              FROM "EXCEPTION_HIST" h
              LEFT JOIN "RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
              LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
             WHERE h."EXCEPTION_DATE" = :P_EXCEPTION_DATE
               AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME" = :P_RULE_CATALOG)
               AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
               AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
        )
        SELECT e."EXCEPTION_ID"            AS "EXCEPTION_ID",
               e."RULE_ID"                 AS "RULE_ID",
               r."RULE_NAME"               AS "RULE_NAME",
               e."ASSET_ID"                AS "ASSET_ID",
               e."EXCEPTION_DATE"          AS "EXCEPTION_DATE",
               e."EXCEPTION_TIME"          AS "EXCEPTION_TIME",
               e."ID_BB_GLOBAL"            AS "ID_BB_GLOBAL",
               e."STATE_ID"                AS "STATE_ID",
               es."NAME"                   AS "EXCEPTION_STATE",
               e."STATUS_ID"               AS "STATUS_ID",
               est_s."NAME"                AS "EXCEPTION_STATUS",
               e."COMMENTS"                AS "COMMENTS",
               e."ISSUE_DESCRIPTION"       AS "ISSUE_DESCRIPTION",
               TO_VARCHAR(e."RESULT_DATA") AS "RESULT_DATA",
               e."SUPPRESS_DATE"           AS "SUPPRESS_DATE",
               e."ASSIGN_TO_ID"            AS "ASSIGN_TO_ID",
               du."USER"                   AS "ASSIGN_TO",
               e."RESULT_TYPE_ID"          AS "RESULT_TYPE_ID",
               ept."NAME"                  AS "PRIORITY",
               est."NAME"                  AS "SEVERITY",
               et."NAME"                   AS "EXCEPTION_TYPE",
               e."CREATED_DATE"            AS "CREATED_DATE",
               e."CREATED_BY"              AS "CREATED_BY",
               e."MODIFIED_DATE"           AS "MODIFIED_DATE",
               e."MODIFIED_BY"             AS "MODIFIED_BY"
        FROM "EXCEPTION_HIST" e
        LEFT JOIN "RULE"                    r     ON r."RULE_ID"                     = e."RULE_ID"
        LEFT JOIN "EXCEPTION_TYPE"          et    ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
        LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept   ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est   ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
        LEFT JOIN "RULE_CATALOG"            rc    ON rc."RULE_CATALOG_ID"            = r."RULE_CATALOG_ID"
        LEFT JOIN "RULE_GROUP"              rg    ON rg."RULE_GROUP_ID"              = rc."RULE_GROUP_ID"
        LEFT JOIN "EXCEPTION_STATE"         es    ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
        LEFT JOIN "EXCEPTION_STATUS"        est_s ON est_s."EXCEPTION_STATUS_ID"     = e."STATUS_ID"
        LEFT JOIN "DM_USER"                 du    ON du."ID"                         = e."ASSIGN_TO_ID"
        WHERE e."EXCEPTION_DATE" = :P_EXCEPTION_DATE
          AND e."BATCH_ID" = (SELECT mb FROM max_batch)
          AND (:P_ASSET_ID          IS NULL OR e."ASSET_ID" = :P_ASSET_ID)
          AND (:P_EXCEPTION_TYPE    IS NULL OR et."NAME"    = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY          IS NULL OR est."NAME"   = :P_SEVERITY)
          AND (:P_PRIORITY          IS NULL OR ept."NAME"   = :P_PRIORITY)
          AND (:P_RULE_CATALOG      IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME" = :P_RULE_CATALOG)
          AND (:P_RULE_NAME         IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_RULE_GROUP        IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
          AND (:P_EXCEPTION_STATE   IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME" = :P_EXCEPTION_STATE)
          AND (:P_ASSIGN_TO         IS NULL OR :P_ASSIGN_TO = 'All' OR du."USER" = :P_ASSIGN_TO)
          AND (:P_RULE_NAME_PATTERN IS NULL OR r."RULE_NAME" ILIKE :P_RULE_NAME_PATTERN)
    );
    RETURN TABLE(res);
END;
$$;
