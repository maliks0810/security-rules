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
    -- Single-pass aggregation: collapse SECURITY_EXCEPTION to one row per
    -- ASSET_ID with MIN_BY / MAX_BY / MAX / COUNT_IF aggregates instead of
    -- FIRST_VALUE OVER + QUALIFY ROW_NUMBER. MIN_BY is a streaming
    -- aggregate (no per-partition sort), so the plan is materially cheaper
    -- than the windowed equivalent. ALL_COMPLETE is derived from
    -- EXCEPTION_COUNT to avoid a second pass. FIGI is sourced from the
    -- most recent SECURITY_EXCEPTION."ID_BB_GLOBAL" via MAX_BY(... RUN_DATE).
    res := (
        WITH filtered AS (
            SELECT
                se."ASSET_ID"                      AS "ASSET_ID",
                se."RUN_DATE"                      AS "RUN_DATE",
                se."ASSIGN_TO_ID"                  AS "ASSIGN_TO_ID",
                se."ID_BB_GLOBAL"                  AS "ID_BB_GLOBAL",
                st."CODE"                          AS "SEVERITY_CODE",
                st."SEVERITY_RANK"                 AS "SEVERITY_RANK",
                ct."CODE"                          AS "CATEGORY_CODE",
                ct."CATEGORY_RANK"                 AS "CATEGORY_RANK",
                et."CODE"                          AS "EXC_TYPE_CODE",
                et."EXCEPTIONTYPERANK"             AS "EXC_TYPE_RANK",
                es."CODE"                          AS "STATUS_CODE"
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
        ),
        per_asset AS (
            SELECT
                "ASSET_ID",
                MAX("RUN_DATE")                                            AS run_date_max,
                MIN_BY("SEVERITY_CODE", "SEVERITY_RANK")                   AS priority_code,
                MIN_BY("CATEGORY_CODE", "CATEGORY_RANK")                   AS severity_code,
                MIN_BY("EXC_TYPE_CODE", "EXC_TYPE_RANK")                   AS type_code,
                MAX_BY("ASSIGN_TO_ID", "RUN_DATE")                         AS assign_to_id_latest,
                MAX_BY("ID_BB_GLOBAL", "RUN_DATE")                         AS id_bb_global_latest,
                COUNT_IF(COALESCE("STATUS_CODE", '') <> 'Complete')        AS open_count
            FROM filtered
            GROUP BY "ASSET_ID"
        )
        SELECT
            pa.run_date_max               AS "EXCEPTION_DATE",
            pa.priority_code              AS "PRIORITY",
            pa.severity_code              AS "SEVERITY",
            pa.type_code                  AS "TYPE",
            du."USER"                     AS "ASSIGN_TO",
            pa."ASSET_ID"                 AS "ASSET_ID",
            pa.id_bb_global_latest        AS "FIGI",
            'XYZ'                         AS "SECURITY_DESCRIPTION",
            'Colman Slain'                AS "TRADER",
            'ABS'                         AS "TRADING_TEAM",
            pa.open_count                 AS "EXCEPTION_COUNT",
            '10:55 AM'                    AS "BBG_LAST_REFRESH",
            (pa.open_count = 0)           AS "ALL_COMPLETE"
        FROM per_asset pa
        LEFT JOIN "DM_USER" du ON du."ID" = pa.assign_to_id_latest
    );
    RETURN TABLE(res);
END;
$$;
