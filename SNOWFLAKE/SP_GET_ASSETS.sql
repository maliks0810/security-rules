CREATE OR REPLACE PROCEDURE SP_GET_ASSETS(
    P_EXCEPTION_TYPE   VARCHAR DEFAULT NULL,
    P_SEVERITY         VARCHAR DEFAULT NULL,
    P_PRIORITY         VARCHAR DEFAULT NULL,
    P_RULE_CATALOG     VARCHAR DEFAULT NULL,
    P_RULE_NAME        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE VARCHAR DEFAULT NULL,
    P_ASSIGN_TO        VARCHAR DEFAULT NULL,
    P_RULE_GROUP       VARCHAR DEFAULT NULL
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
    res := (
        WITH filtered AS (
            SELECT
                e."ASSET_ID",
                e."EXCEPTION_TIME",
                e."ID_BB_GLOBAL",
                ept."NAME"       AS priority_name,
                ept."SORT_ORDER" AS priority_rank,
                est."NAME"       AS severity_name,
                est."SORT_ORDER" AS severity_rank,
                et."NAME"        AS type_name,
                et."SORT_ORDER"  AS type_rank,
                es."NAME"        AS state_name,
                du."USER"        AS assign_to_user
            FROM "EXCEPTION" e
            JOIN "RULE" r
              ON r."RULE_ID" = e."RULE_ID"
            LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept
              ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
            LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est
              ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
            LEFT JOIN "EXCEPTION_TYPE" et
              ON et."EXCEPTION_TYPE_ID" = r."EXCEPTION_TYPE_ID"
            LEFT JOIN "RULE_CATALOG" rc
              ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            LEFT JOIN "RULE_GROUP" rg
              ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
            LEFT JOIN "EXCEPTION_STATE" es
              ON es."EXCEPTION_STATE_ID" = e."STATE_ID"
            LEFT JOIN "DM_USER" du
              ON du."ID" = e."ASSIGN_TO_ID"
            WHERE (:P_EXCEPTION_TYPE   IS NULL OR et."NAME"  = :P_EXCEPTION_TYPE)
              AND (:P_SEVERITY         IS NULL OR est."NAME" = :P_SEVERITY)
              AND (:P_PRIORITY         IS NULL OR ept."NAME" = :P_PRIORITY)
              AND (:P_RULE_GROUP       IS NULL OR :P_RULE_GROUP       = 'All' OR rg."NAME"      = :P_RULE_GROUP)
              AND (:P_RULE_CATALOG     IS NULL OR :P_RULE_CATALOG     = 'All' OR rc."NAME"      = :P_RULE_CATALOG)
              AND (:P_RULE_NAME        IS NULL OR :P_RULE_NAME        = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
              AND (:P_EXCEPTION_STATE IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME"      = :P_EXCEPTION_STATE)
              AND (:P_ASSIGN_TO        IS NULL OR :P_ASSIGN_TO        = 'All' OR du."USER"      = :P_ASSIGN_TO)
        )
        SELECT
            MAX("EXCEPTION_TIME")                                  AS "EXCEPTION_DATE",
            MIN_BY(priority_name, priority_rank)                   AS "PRIORITY",
            MIN_BY(severity_name, severity_rank)                   AS "SEVERITY",
            MIN_BY(type_name, type_rank)                           AS "TYPE",
            MAX_BY(assign_to_user, "EXCEPTION_TIME")               AS "ASSIGN_TO",
            "ASSET_ID"                                             AS "ASSET_ID",
            MAX_BY("ID_BB_GLOBAL", "EXCEPTION_TIME")               AS "FIGI",
            'XYZ'                                                  AS "SECURITY_DESCRIPTION",
            'Colman Slain'                                         AS "TRADER",
            'ABS'                                                  AS "TRADING_TEAM",
            COUNT_IF(COALESCE(state_name, '') <> 'Complete')      AS "EXCEPTION_COUNT",
            '10:55 AM'                                             AS "BBG_LAST_REFRESH",
            -- ALL_COMPLETE: asset-level property, true iff every EXCEPTION row
            -- for the asset (across all statuses, ignoring user filters) has
            -- status 'Complete'. Computed via a correlated subquery against
            -- the unfiltered EXCEPTION table.
            (SELECT COUNT(*) > 0
                    AND COUNT_IF(COALESCE(es_all."NAME", '') <> 'Complete') = 0
               FROM "EXCEPTION" e_all
               LEFT JOIN "EXCEPTION_STATE" es_all
                 ON es_all."EXCEPTION_STATE_ID" = e_all."STATE_ID"
              WHERE e_all."ASSET_ID" = filtered."ASSET_ID")        AS "ALL_COMPLETE"
        FROM filtered
        GROUP BY "ASSET_ID"
        ORDER BY "ASSET_ID"
    );
    RETURN TABLE(res);
END;
$$;
