DROP FUNCTION IF EXISTS public."GET_ASSETS"();
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text);
DROP FUNCTION IF EXISTS public."GET_ASSETS"(text, text, text);

CREATE OR REPLACE FUNCTION public."GET_ASSETS"(
    p_exception_type text DEFAULT NULL,
    p_severity       text DEFAULT NULL,
    p_priority       text DEFAULT NULL
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
    "BBG_LAST_REFRESH"     text
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
                      LEFT JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      LEFT JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity       IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority       IS NULL OR st2."CODE" = p_priority)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "PRIORITY",
           (SELECT ranked."CODE"
              FROM (SELECT ct2."CODE",
                           RANK() OVER (ORDER BY ct2."CATEGORY_RANK" ASC) AS rk
                      FROM public."SECURITY_EXCEPTION" se2
                      JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                      LEFT JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      LEFT JOIN public."SEVERITY_TYPE" st2
                        ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity       IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority       IS NULL OR st2."CODE" = p_priority)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "SEVERITY",
           (SELECT ranked."CODE"
              FROM (SELECT et2."CODE",
                           RANK() OVER (ORDER BY et2."EXCEPTIONTYPERANK" ASC) AS rk
                      FROM public."SECURITY_EXCEPTION" se2
                      JOIN public."EXCEPTION_TYPE" et2
                        ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
                      LEFT JOIN public."CATEGORY_TYPE" ct2
                        ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
                      LEFT JOIN public."SEVERITY_TYPE" st2
                        ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
                     WHERE se2."ASSET_ID" = se."ASSET_ID"
                       AND (p_exception_type IS NULL OR et2."CODE" = p_exception_type)
                       AND (p_severity       IS NULL OR ct2."CODE" = p_severity)
                       AND (p_priority       IS NULL OR st2."CODE" = p_priority)) ranked
             WHERE ranked.rk = 1
             LIMIT 1)        AS "TYPE",
           se."ASSIGN_TO"     AS "ASSIGN_TO",
           se."ASSET_ID"      AS "ASSET_ID",
           'BBG00G6M2LZ2'     AS "FIGI",
           'XYZ'              AS "SECURITY_DESCRIPTION",
           'Colman Slain'     AS "TRADER",
           'ABS'              AS "TRADING_TEAM",
           (SELECT COUNT(*)::int
              FROM public."SECURITY_EXCEPTION" se2
              JOIN public."SEVERITY_TYPE" st2 ON st2."SEVERITY_TYPE_ID" = se2."SEVERITY_TYPE_ID"
              JOIN public."RULE"          r2  ON r2."RULE_ID"          = se2."RULE_ID"
              LEFT JOIN public."EXCEPTION_TYPE" et2
                ON et2."EXCEPTION_TYPE_ID" = se2."EXCEPTION_TYPE_ID"
              LEFT JOIN public."CATEGORY_TYPE" ct2
                ON ct2."CATEGORY_TYPE_ID" = se2."CATEGORY_TYPE_ID"
             WHERE se2."ASSET_ID" = se."ASSET_ID"
               AND (p_exception_type IS NULL OR et2."CODE" = p_exception_type)
               AND (p_severity       IS NULL OR ct2."CODE" = p_severity)
               AND (p_priority       IS NULL OR st2."CODE" = p_priority)) AS "EXCEPTION_COUNT",
           '10:55 AM'         AS "BBG_LAST_REFRESH"
    FROM public."SECURITY_EXCEPTION" se
    JOIN public."SEVERITY_TYPE" st
      ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
    JOIN public."CATEGORY_TYPE" ct
      ON ct."CATEGORY_TYPE_ID" = se."CATEGORY_TYPE_ID"
    LEFT JOIN public."EXCEPTION_TYPE" et
      ON et."EXCEPTION_TYPE_ID" = se."EXCEPTION_TYPE_ID"
    WHERE (p_exception_type IS NULL OR et."CODE" = p_exception_type)
      AND (p_severity       IS NULL OR ct."CODE" = p_severity)
      AND (p_priority       IS NULL OR st."CODE" = p_priority)
    ORDER BY se."ASSET_ID", se."RUN_DATE" DESC;
$$;
