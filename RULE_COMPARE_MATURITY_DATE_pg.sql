-- Postgres conversion of RULE_COMPARE_MATURITY_DATE.sql (Snowflake).
-- The source views (common.BBG_INTRADAY_SECURITY_VW, tdc.SECURITY_CURRENT_VW)
-- and UDF common.UDF_GET_BBG_MATURITY_DATE come from Snowflake and need
-- local equivalents (or stubs) before this function can be executed here.


CREATE OR REPLACE FUNCTION public."RULE_BBG_COMPARE_MATURITY_DATE"(
    "ALADDIN_ID"   varchar(15),
    "ID_BB_GLOBAL" varchar(15)
)
RETURNS TABLE(
    "ALADDIN_ID"            varchar,
    "ID_BB_GLOBAL"          varchar,
    "BBG_MATURITY_DATE"     varchar,
    "ALADDIN_MATURITY_DATE" varchar,
    "ISSUE_DESCRIPTION"     varchar
)
LANGUAGE sql
AS $$
   
    SELECT
       '38384LJ83' AS  "ALADDIN_ID",
        'BBG01Z2F2QF9' AS  "ID_BB_GLOBAL",
       '4/18/2029' AS  "BBG_MATURITY_DATE",
        '5/15/2029' AS "ALADDIN_MATURITY_DATE",
        'BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
         '5/15/2029' || ' BBG Maturity:' ||
         '4/18/2029'  AS "ISSUE_DESCRIPTION"
   
$$;
