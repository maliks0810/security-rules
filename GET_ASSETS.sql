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
    res := (
        SELECT
            se."RUN_DATE"     AS "EXCEPTION_DATE",
            (
                SELECT st2."CODE"
                FROM "SECURITY_EXCEPTION" se2
                JOIN "SEVERITY_TYPE" st2 ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                JOIN "RULE"          r2  ON r2."RULE_ID"           = se2."RULE_ID"
                LEFT JOIN "RULE_TYPE"        rt2 ON rt2."RULE_TYPE_ID"        = r2."RULE_TYPE_ID"
                LEFT JOIN "EXCEPTION_TYPE"   et2 ON et2."EXCEPTION_TYPE_ID"   = se2."EXCEPTION_TYPE_ID"
                LEFT JOIN "CATEGORY_TYPE"    ct2 ON ct2."CATEGORY_TYPE_ID"    = se2."CATEGORY_TYPE_ID"
                LEFT JOIN "EXCEPTION_STATUS" es2 ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                LEFT JOIN "DM_USER"          du2 ON du2."ID"                  = se2."ASSIGN_TO_ID"
                WHERE se2."ASSET_ID" = se."ASSET_ID"
                  AND (:P_EXCEPTION_TYPE IS NULL OR et2."CODE" = :P_EXCEPTION_TYPE)
                  AND (:P_SEVERITY       IS NULL OR ct2."CODE" = :P_SEVERITY)
                  AND (:P_PRIORITY       IS NULL OR st2."CODE" = :P_PRIORITY)
                  AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rt2."NAME"     = :P_RULE_TYPE)
                  AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r2."RULE_NAME" = :P_RULE_NAME)
                  AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es2."CODE" = :P_EXCEPTION_STATUS)
                  AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du2."USER"      = :P_ASSIGN_TO)
                QUALIFY RANK() OVER (ORDER BY st2."SEVERITY_RANK" ASC) = 1
                LIMIT 1
            ) AS "PRIORITY",
            (
                SELECT ct2."CODE"
                FROM "SECURITY_EXCEPTION" se2
                JOIN "CATEGORY_TYPE" ct2 ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                JOIN "RULE"          r2  ON r2."RULE_ID"           = se2."RULE_ID"
                LEFT JOIN "RULE_TYPE"        rt2 ON rt2."RULE_TYPE_ID"        = r2."RULE_TYPE_ID"
                LEFT JOIN "EXCEPTION_TYPE"   et2 ON et2."EXCEPTION_TYPE_ID"   = se2."EXCEPTION_TYPE_ID"
                LEFT JOIN "SEVERITY_TYPE"    st2 ON st2."SEVERITY_TYPE_ID"    = se2."SEVERITY_TYPE_ID"
                LEFT JOIN "EXCEPTION_STATUS" es2 ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                LEFT JOIN "DM_USER"          du2 ON du2."ID"                  = se2."ASSIGN_TO_ID"
                WHERE se2."ASSET_ID" = se."ASSET_ID"
                  AND (:P_EXCEPTION_TYPE IS NULL OR et2."CODE" = :P_EXCEPTION_TYPE)
                  AND (:P_SEVERITY       IS NULL OR ct2."CODE" = :P_SEVERITY)
                  AND (:P_PRIORITY       IS NULL OR st2."CODE" = :P_PRIORITY)
                  AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rt2."NAME"     = :P_RULE_TYPE)
                  AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r2."RULE_NAME" = :P_RULE_NAME)
                  AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es2."CODE" = :P_EXCEPTION_STATUS)
                  AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du2."USER"      = :P_ASSIGN_TO)
                QUALIFY RANK() OVER (ORDER BY ct2."CATEGORY_RANK" ASC) = 1
                LIMIT 1
            ) AS "SEVERITY",
            (
                SELECT et2."CODE"
                FROM "SECURITY_EXCEPTION" se2
                JOIN "EXCEPTION_TYPE" et2 ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                JOIN "RULE"           r2  ON r2."RULE_ID"            = se2."RULE_ID"
                LEFT JOIN "RULE_TYPE"        rt2 ON rt2."RULE_TYPE_ID"        = r2."RULE_TYPE_ID"
                LEFT JOIN "CATEGORY_TYPE"    ct2 ON ct2."CATEGORY_TYPE_ID"    = se2."CATEGORY_TYPE_ID"
                LEFT JOIN "SEVERITY_TYPE"    st2 ON st2."SEVERITY_TYPE_ID"    = se2."SEVERITY_TYPE_ID"
                LEFT JOIN "EXCEPTION_STATUS" es2 ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                LEFT JOIN "DM_USER"          du2 ON du2."ID"                  = se2."ASSIGN_TO_ID"
                WHERE se2."ASSET_ID" = se."ASSET_ID"
                  AND (:P_EXCEPTION_TYPE IS NULL OR et2."CODE" = :P_EXCEPTION_TYPE)
                  AND (:P_SEVERITY       IS NULL OR ct2."CODE" = :P_SEVERITY)
                  AND (:P_PRIORITY       IS NULL OR st2."CODE" = :P_PRIORITY)
                  AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rt2."NAME"     = :P_RULE_TYPE)
                  AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r2."RULE_NAME" = :P_RULE_NAME)
                  AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es2."CODE" = :P_EXCEPTION_STATUS)
                  AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du2."USER"      = :P_ASSIGN_TO)
                QUALIFY RANK() OVER (ORDER BY et2."EXCEPTIONTYPERANK" ASC) = 1
                LIMIT 1
            ) AS "TYPE",
            du."USER"         AS "ASSIGN_TO",
            se."ASSET_ID"     AS "ASSET_ID",
            'BBG00G6M2LZ2'    AS "FIGI",
            'XYZ'             AS "SECURITY_DESCRIPTION",
            'Colman Slain'    AS "TRADER",
            'ABS'             AS "TRADING_TEAM",
            (
                SELECT CAST(COUNT(*) AS NUMBER)
                FROM "SECURITY_EXCEPTION" se2
                JOIN "SEVERITY_TYPE" st2 ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                JOIN "RULE"          r2  ON r2."RULE_ID"           = se2."RULE_ID"
                LEFT JOIN "RULE_TYPE"        rt2 ON rt2."RULE_TYPE_ID"        = r2."RULE_TYPE_ID"
                LEFT JOIN "EXCEPTION_TYPE"   et2 ON et2."EXCEPTION_TYPE_ID"   = se2."EXCEPTION_TYPE_ID"
                LEFT JOIN "CATEGORY_TYPE"    ct2 ON ct2."CATEGORY_TYPE_ID"    = se2."CATEGORY_TYPE_ID"
                LEFT JOIN "EXCEPTION_STATUS" es2 ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                LEFT JOIN "DM_USER"          du2 ON du2."ID"                  = se2."ASSIGN_TO_ID"
                WHERE se2."ASSET_ID" = se."ASSET_ID"
                  AND (:P_EXCEPTION_TYPE IS NULL OR et2."CODE" = :P_EXCEPTION_TYPE)
                  AND (:P_SEVERITY       IS NULL OR ct2."CODE" = :P_SEVERITY)
                  AND (:P_PRIORITY       IS NULL OR st2."CODE" = :P_PRIORITY)
                  AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rt2."NAME"     = :P_RULE_TYPE)
                  AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r2."RULE_NAME" = :P_RULE_NAME)
                  AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es2."CODE" = :P_EXCEPTION_STATUS)
                  AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du2."USER"      = :P_ASSIGN_TO)
            ) AS "EXCEPTION_COUNT",
            '10:55 AM'        AS "BBG_LAST_REFRESH",
            (
                SELECT COUNT(*) > 0
                   AND COUNT_IF(COALESCE(es3."CODE", '') <> 'Complete') = 0
                FROM "SECURITY_EXCEPTION" se3
                JOIN "SEVERITY_TYPE" st3 ON st3."SEVERITY_TYPE_ID" = se3."SEVERITY_TYPE_ID"
                JOIN "RULE"          r3  ON r3."RULE_ID"           = se3."RULE_ID"
                LEFT JOIN "RULE_TYPE"        rt3 ON rt3."RULE_TYPE_ID"        = r3."RULE_TYPE_ID"
                LEFT JOIN "EXCEPTION_TYPE"   et3 ON et3."EXCEPTION_TYPE_ID"   = se3."EXCEPTION_TYPE_ID"
                LEFT JOIN "CATEGORY_TYPE"    ct3 ON ct3."CATEGORY_TYPE_ID"    = se3."CATEGORY_TYPE_ID"
                LEFT JOIN "EXCEPTION_STATUS" es3 ON es3."EXCEPTION_STATUS_ID" = se3."EXCEPTION_STATUS_ID"
                LEFT JOIN "DM_USER"          du3 ON du3."ID"                  = se3."ASSIGN_TO_ID"
                WHERE se3."ASSET_ID" = se."ASSET_ID"
                  AND (:P_EXCEPTION_TYPE IS NULL OR et3."CODE" = :P_EXCEPTION_TYPE)
                  AND (:P_SEVERITY       IS NULL OR ct3."CODE" = :P_SEVERITY)
                  AND (:P_PRIORITY       IS NULL OR st3."CODE" = :P_PRIORITY)
                  AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rt3."NAME"     = :P_RULE_TYPE)
                  AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r3."RULE_NAME" = :P_RULE_NAME)
                  AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es3."CODE" = :P_EXCEPTION_STATUS)
                  AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du3."USER"      = :P_ASSIGN_TO)
            ) AS "ALL_COMPLETE"
        FROM "SECURITY_EXCEPTION" se
        JOIN "RULE" r ON r."RULE_ID" = se."RULE_ID"
        LEFT JOIN "RULE_TYPE"        rtj ON rtj."RULE_TYPE_ID"     = r."RULE_TYPE_ID"
        LEFT JOIN "EXCEPTION_TYPE"   et  ON et."EXCEPTION_TYPE_ID" = se."EXCEPTION_TYPE_ID"
        LEFT JOIN "CATEGORY_TYPE"    ct  ON ct."CATEGORY_TYPE_ID"  = se."CATEGORY_TYPE_ID"
        LEFT JOIN "SEVERITY_TYPE"    st  ON st."SEVERITY_TYPE_ID"  = se."SEVERITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_STATUS" es  ON es."EXCEPTION_STATUS_ID" = se."EXCEPTION_STATUS_ID"
        LEFT JOIN "DM_USER"          du  ON du."ID"                  = se."ASSIGN_TO_ID"
        WHERE (:P_EXCEPTION_TYPE IS NULL OR et."CODE" = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY       IS NULL OR ct."CODE" = :P_SEVERITY)
          AND (:P_PRIORITY       IS NULL OR st."CODE" = :P_PRIORITY)
          AND (:P_RULE_TYPE      IS NULL OR :P_RULE_TYPE = 'All' OR rtj."NAME"    = :P_RULE_TYPE)
          AND (:P_RULE_NAME      IS NULL OR :P_RULE_NAME = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es."CODE" = :P_EXCEPTION_STATUS)
          AND (:P_ASSIGN_TO      IS NULL OR :P_ASSIGN_TO = 'All' OR du."USER"      = :P_ASSIGN_TO)
        QUALIFY ROW_NUMBER() OVER (
            PARTITION BY se."ASSET_ID"
            ORDER BY se."RUN_DATE" DESC
        ) = 1
    );
    RETURN TABLE(res);
END;
$$;
