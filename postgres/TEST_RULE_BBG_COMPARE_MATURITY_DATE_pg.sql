-- TEST stub for RULE_BBG_COMPARE_MATURITY_DATE.
-- Returns zero rows so ExecuteRules treats existing exceptions for this
-- rule as untouched and marks them Complete. Re-apply
-- RULE_BBG_COMPARE_MATURITY_DATE_pg.sql afterwards to restore the real
-- function.

CREATE OR REPLACE FUNCTION public."RULE_BBG_COMPARE_MATURITY_DATE"(
    "ALADDIN_ID"   character varying,
    "ID_BB_GLOBAL" character varying
)
RETURNS TABLE(
    "ALADDIN_ID"            character varying,
    "ID_BB_GLOBAL"          character varying,
    "BBG_MATURITY_DATE"     character varying,
    "ALADDIN_MATURITY_DATE" character varying,
    "ISSUE_DESCRIPTION"     character varying
)
LANGUAGE sql
AS $$
    SELECT NULL::character varying,
           NULL::character varying,
           NULL::character varying,
           NULL::character varying,
           NULL::character varying
    WHERE FALSE;
$$;
