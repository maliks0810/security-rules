DROP FUNCTION IF EXISTS public."GET_ASSETS"();
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text, text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text, text, text, text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text, text, text, text, text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text, text, text, text, text, text);

CREATE OR REPLACE FUNCTION public."GET_ASSETS"(
    p_exception_type   text DEFAULT NULL,
    p_severity         text DEFAULT NULL,
    p_priority         text DEFAULT NULL,
    p_rule_type        text DEFAULT NULL,
    p_rule_name        text DEFAULT NULL,
    p_exception_status text DEFAULT NULL,
    p_assign_to        text DEFAULT NULL
)
RETURNS TABLE(
    "EXCEPTION_DATE"       timestamp without time zone,
    "PRIORITY"             text,
    "SEVERITY"             text,
    "TYPE"                 text,
    "ASSIGN_TO"            text,
    "ASSET_ID"             character varying,
    "FIGI"                 text,
    "SECURITY_DESCRIPTION" text,
    "TRADER"               text,
    "TRADING_TEAM"         text,
    "EXCEPTION_COUNT"      integer,
    "BBG_LAST_REFRESH"     text,
    "ALL_COMPLETE"         boolean
)
LANGUAGE sql
AS $$
    SELECT DISTINCT ON (se."ASSET_ID")
           se."RUN_DATE"      AS "EXCEPTION_DATE",
           (SELECT ranked."CODE"
              FROM (SELECT st2."CODE",
                           RANK() OVER (ORDER BY st2."SEVERITY_RANK" ASC) AS rk
                      FROM public."SECURITY_EXCEPTION" se2
                      JOIN public."SEVERITY_TYPE" st2
                        ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                      JOIN public."RULE" r2
                        ON r2."RULE_ID" = se2."RULE_ID"
                      LEFT JOIN public."RULE_TYPE" rt2
                        ON rt2."RULE_TYPE_ID" = r2."RULE_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      LEFT JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_STATUS" es2
                        ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                      LEFT JOIN public."DM_USER" du2
                        ON du2."ID" = se2."ASSIGN_TO_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type   IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity         IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority         IS NULL OR st2."CODE" = p_priority)
                       AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rt2."NAME"     = p_rule_type)
                       AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r2."RULE_NAME" = p_rule_name)
                       AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es2."CODE"    = p_exception_status)
                       AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du2."USER"    = p_assign_to)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "PRIORITY",
           (SELECT ranked."CODE"
              FROM (SELECT ct2."CODE",
                           RANK() OVER (ORDER BY ct2."CATEGORY_RANK" ASC) AS rk
                      FROM public."SECURITY_EXCEPTION" se2
                      JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                      JOIN public."RULE" r2
                        ON r2."RULE_ID" = se2."RULE_ID"
                      LEFT JOIN public."RULE_TYPE" rt2
                        ON rt2."RULE_TYPE_ID" = r2."RULE_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      LEFT JOIN public."SEVERITY_TYPE" st2
                        ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_STATUS" es2
                        ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                      LEFT JOIN public."DM_USER" du2
                        ON du2."ID" = se2."ASSIGN_TO_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type   IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity         IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority         IS NULL OR st2."CODE" = p_priority)
                       AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rt2."NAME"     = p_rule_type)
                       AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r2."RULE_NAME" = p_rule_name)
                       AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es2."CODE"    = p_exception_status)
                       AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du2."USER"    = p_assign_to)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "SEVERITY",
           (SELECT ranked."CODE"
              FROM (SELECT et2."CODE",
                           RANK() OVER (ORDER BY et2."EXCEPTIONTYPERANK" ASC) AS rk
                      FROM public."SECURITY_EXCEPTION" se2
                      JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      JOIN public."RULE" r2
                        ON r2."RULE_ID" = se2."RULE_ID"
                      LEFT JOIN public."RULE_TYPE" rt2
                        ON rt2."RULE_TYPE_ID" = r2."RULE_TYPE_ID"
                      LEFT JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                      LEFT JOIN public."SEVERITY_TYPE" st2
                        ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_STATUS" es2
                        ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
                      LEFT JOIN public."DM_USER" du2
                        ON du2."ID" = se2."ASSIGN_TO_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type   IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity         IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority         IS NULL OR st2."CODE" = p_priority)
                       AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rt2."NAME"     = p_rule_type)
                       AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r2."RULE_NAME" = p_rule_name)
                       AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es2."CODE"    = p_exception_status)
                       AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du2."USER"    = p_assign_to)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "TYPE",
           du."USER"          AS "ASSIGN_TO",
           se."ASSET_ID"      AS "ASSET_ID",
           'BBG00G6M2LZ2'     AS "FIGI",
           'XYZ'              AS "SECURITY_DESCRIPTION",
           'Colman Slain'     AS "TRADER",
           'ABS'              AS "TRADING_TEAM",
           (SELECT COUNT(*)::int
              FROM public."SECURITY_EXCEPTION" se2
              JOIN public."SEVERITY_TYPE" st2 ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
              JOIN public."RULE"          r2  ON r2."RULE_ID"          = se2."RULE_ID"
              LEFT JOIN public."RULE_TYPE" rt2
                ON rt2."RULE_TYPE_ID" = r2."RULE_TYPE_ID"
              LEFT JOIN public."EXCEPTION_TYPE" et2
                ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
              LEFT JOIN public."CATEGORY_TYPE" ct2
                ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
              LEFT JOIN public."EXCEPTION_STATUS" es2
                ON es2."EXCEPTION_STATUS_ID" = se2."EXCEPTION_STATUS_ID"
              LEFT JOIN public."DM_USER" du2
                ON du2."ID" = se2."ASSIGN_TO_ID"
             WHERE se2."ASSET_ID" = se."ASSET_ID"
               AND (p_exception_type   IS NULL OR et2."CODE" = p_exception_type)
               AND (p_severity         IS NULL OR ct2."CODE" = p_severity)
               AND (p_priority         IS NULL OR st2."CODE" = p_priority)
               AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rt2."NAME"     = p_rule_type)
               AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r2."RULE_NAME" = p_rule_name)
               AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es2."CODE"    = p_exception_status)
               AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du2."USER"    = p_assign_to)
               AND (es2."CODE" IS NULL OR es2."CODE" <> 'Complete')) AS "EXCEPTION_COUNT",
           '10:55 AM'         AS "BBG_LAST_REFRESH",
           (SELECT COUNT(*) > 0
              AND COUNT(*) FILTER (WHERE es3."CODE" IS DISTINCT FROM 'Complete') = 0
              FROM public."SECURITY_EXCEPTION" se3
              JOIN public."SEVERITY_TYPE" st3 ON st3."SEVERITY_TYPE_ID" = se3."SEVERITY_TYPE_ID"
              JOIN public."RULE"          r3  ON r3."RULE_ID"          = se3."RULE_ID"
              LEFT JOIN public."RULE_TYPE" rt3
                ON rt3."RULE_TYPE_ID" = r3."RULE_TYPE_ID"
              LEFT JOIN public."EXCEPTION_TYPE" et3
                ON et3."EXCEPTION_TYPE_ID" = se3."EXCEPTION_TYPE_ID"
              LEFT JOIN public."CATEGORY_TYPE" ct3
                ON ct3."CATEGORY_TYPE_ID" = se3."CATEGORY_TYPE_ID"
              LEFT JOIN public."EXCEPTION_STATUS" es3
                ON es3."EXCEPTION_STATUS_ID" = se3."EXCEPTION_STATUS_ID"
              LEFT JOIN public."DM_USER" du3
                ON du3."ID" = se3."ASSIGN_TO_ID"
             WHERE se3."ASSET_ID" = se."ASSET_ID"
               AND (p_exception_type   IS NULL OR et3."CODE" = p_exception_type)
               AND (p_severity         IS NULL OR ct3."CODE" = p_severity)
               AND (p_priority         IS NULL OR st3."CODE" = p_priority)
               AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rt3."NAME"     = p_rule_type)
               AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r3."RULE_NAME" = p_rule_name)
               AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es3."CODE"    = p_exception_status)
               AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du3."USER"    = p_assign_to)) AS "ALL_COMPLETE"
    FROM public."SECURITY_EXCEPTION" se
    JOIN public."SEVERITY_TYPE" st
      ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
    JOIN public."CATEGORY_TYPE" ct
      ON ct."CATEGORY_TYPE_ID" = se."CATEGORY_TYPE_ID"
    JOIN public."RULE" r
      ON r."RULE_ID" = se."RULE_ID"
    LEFT JOIN public."RULE_TYPE" rtj
      ON rtj."RULE_TYPE_ID" = r."RULE_TYPE_ID"
    LEFT JOIN public."EXCEPTION_TYPE" et
      ON et."EXCEPTION_TYPE_ID" = se."EXCEPTION_TYPE_ID"
    LEFT JOIN public."EXCEPTION_STATUS" es
      ON es."EXCEPTION_STATUS_ID" = se."EXCEPTION_STATUS_ID"
    LEFT JOIN public."DM_USER" du
      ON du."ID" = se."ASSIGN_TO_ID"
    WHERE (p_exception_type   IS NULL OR et."CODE" = p_exception_type)
      AND (p_severity         IS NULL OR ct."CODE" = p_severity)
      AND (p_priority         IS NULL OR st."CODE" = p_priority)
      AND (p_rule_type        IS NULL OR p_rule_type        = 'All' OR rtj."NAME"    = p_rule_type)
      AND (p_rule_name        IS NULL OR p_rule_name        = 'All' OR r."RULE_NAME" = p_rule_name)
      AND (p_exception_status IS NULL OR p_exception_status = 'All' OR es."CODE"     = p_exception_status)
      AND (p_assign_to        IS NULL OR p_assign_to        = 'All' OR du."USER"     = p_assign_to)
    ORDER BY se."ASSET_ID", se."RUN_DATE" DESC;
$$;
