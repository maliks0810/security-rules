CREATE OR REPLACE FUNCTION public."GET_ASSETS"()
RETURNS TABLE(
    "EXCEPTION_DATE"       timestamp,
    "PRIORITY"             text,
    "TYPE"                 text,
    "ASSIGN_TO"            text,
    "ASSET_ID"             varchar(30),
    "FIGI"                 text,
    "SECURITY_DESCRIPTION" text,
    "TRADER"               text,
    "TRADING_TEAM"         text,
    "EXCEPTION_COUNT"      integer,
    "BBG_LAST_REFRESH"     text
)
LANGUAGE sql
AS $$
    SELECT DISTINCT ON (se."ALADDIN_ID")
           se."RUN_DATE"      AS "EXCEPTION_DATE",
           st."CODE"          AS "PRIORITY",
           'Security Set up'  AS "TYPE",
           se."ASSIGN_TO"     AS "ASSIGN_TO",
           se."ALADDIN_ID"    AS "ASSET_ID",
           'BBG00G6M2LZ2'     AS "FIGI",
           'XYZ'              AS "SECURITY_DESCRIPTION",
           'Colman Slain'     AS "TRADER",
           'ABS'              AS "TRADING_TEAM",
           7                  AS "EXCEPTION_COUNT",
           '10:55 AM'         AS "BBG_LAST_REFRESH"
    FROM public."SECURITY_EXCEPTION" se
    JOIN public."SEVERITY_TYPE" st
      ON st."SEVERITY_TYPE_ID" = se."SEVERITY_TYPE_ID"
    ORDER BY se."ALADDIN_ID", se."RUN_DATE" DESC;
$$;
