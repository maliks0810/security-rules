CREATE OR REPLACE PROCEDURE GET_ASSETS(
    P_EXCEPTION_TYPE   VARCHAR DEFAULT NULL,
    P_SEVERITY         VARCHAR DEFAULT NULL,
    P_PRIORITY         VARCHAR DEFAULT NULL,
    P_RULE_TYPE        VARCHAR DEFAULT NULL,
    P_RULE_NAME        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATUS VARCHAR DEFAULT NULL,
    P_ASSIGN_TO        VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "EXCEPTION_DATE"       TIMESTAMP_NTZ,
    "PRIORITY"             VARCHAR,
    "SEVERITY"             VARCHAR,
    "TYPE"                 VARCHAR,
    "ASSIGN_TO"            VARCHAR,
    "ASSET_ID"             VARCHAR,
    "FIGI"                 VARCHAR,
    "SECURITY_DESCRIPTION" VARCHAR,
    "TRADER"               VARCHAR,
    "TRADING_TEAM"         VARCHAR,
    "EXCEPTION_COUNT"      NUMBER,
    "BBG_LAST_REFRESH"     VARCHAR,
    "ALL_COMPLETE"         BOOLEAN
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- Snowflake cannot evaluate correlated scalar subqueries that contain
    -- window functions / LIMIT (unlike Postgres), so the per-asset rollups
    -- are computed in a single pass with window functions instead.
    res := (
        WITH filtered AS (
            SELECT
                se."ASSET_ID"            AS "ASSET_ID",
                se."RUN_DATE"            AS "RUN_DATE",
                du."USER"                AS "ASSIGN_TO_USER",
                st."CODE"                AS "SEVERITY_CODE",
                st."SEVERITY_RANK"       AS "SEVERITY_RANK",
                ct."CODE"                AS "CATEGORY_CODE",
                ct."CATEGORY_RANK"       AS "CATEGORY_RANK",
                et."CODE"                AS "EXC_TYPE_CODE",
                et."EXCEPTIONTYPERANK"   AS "EXC_TYPE_RANK",
                es."CODE"                AS "STATUS_CODE"
            FROM "SECURITY_EXCEPTION" se
            JOIN "RULE"          r  ON r."RULE_ID"           = se."RULE_ID"
            JOIN "SEVERITY_TYPE" st ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
            JOIN "CATEGORY_TYPE" ct ON ct."CATEGORY_TYPE_ID" = se."CATEGORY_TYPE_ID"
            LEFT JOIN "RULE_TYPE"        rt ON rt."RULE_TYPE_ID"        = r."RULE_TYPE_ID"
            LEFT JOIN "EXCEPTION_TYPE"   et ON et."EXCEPTION_TYPE_ID"   = se."EXCEPTION_TYPE_ID"
            LEFT JOIN "EXCEPTION_STATUS" es ON es."EXCEPTION_STATUS_ID" = se."EXCEPTION_STATUS_ID"
            LEFT JOIN "DM_USER"          du ON du."ID"                  = se."ASSIGN_TO_ID"
            WHERE (:P_EXCEPTION_TYPE   IS NULL OR et."CODE" = :P_EXCEPTION_TYPE)
              AND (:P_SEVERITY         IS NULL OR ct."CODE" = :P_SEVERITY)
              AND (:P_PRIORITY         IS NULL OR st."CODE" = :P_PRIORITY)
              AND (:P_RULE_TYPE        IS NULL OR :P_RULE_TYPE        = 'All' OR rt."NAME"     = :P_RULE_TYPE)
              AND (:P_RULE_NAME        IS NULL OR :P_RULE_NAME        = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
              AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es."CODE"     = :P_EXCEPTION_STATUS)
              AND (:P_ASSIGN_TO        IS NULL OR :P_ASSIGN_TO        = 'All' OR du."USER"     = :P_ASSIGN_TO)
        )
        SELECT
            "RUN_DATE"                 AS "EXCEPTION_DATE",
            FIRST_VALUE("SEVERITY_CODE") OVER (
                PARTITION BY "ASSET_ID" ORDER BY "SEVERITY_RANK" NULLS LAST
            )                          AS "PRIORITY",
            FIRST_VALUE("CATEGORY_CODE") OVER (
                PARTITION BY "ASSET_ID" ORDER BY "CATEGORY_RANK" NULLS LAST
            )                          AS "SEVERITY",
            FIRST_VALUE("EXC_TYPE_CODE") OVER (
                PARTITION BY "ASSET_ID" ORDER BY "EXC_TYPE_RANK" NULLS LAST
            )                          AS "TYPE",
            "ASSIGN_TO_USER"           AS "ASSIGN_TO",
            "ASSET_ID"                 AS "ASSET_ID",
            'BBG00G6M2LZ2'             AS "FIGI",
            'XYZ'                      AS "SECURITY_DESCRIPTION",
            'Colman Slain'             AS "TRADER",
            'ABS'                      AS "TRADING_TEAM",
            COUNT(*) OVER (PARTITION BY "ASSET_ID")            AS "EXCEPTION_COUNT",
            '10:55 AM'                 AS "BBG_LAST_REFRESH",
            COUNT_IF(COALESCE("STATUS_CODE", '') <> 'Complete')
                OVER (PARTITION BY "ASSET_ID") = 0             AS "ALL_COMPLETE"
        FROM filtered
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY "ASSET_ID" ORDER BY "RUN_DATE" DESC
        ) = 1
    );
    RETURN TABLE(res);
END;
$$;
