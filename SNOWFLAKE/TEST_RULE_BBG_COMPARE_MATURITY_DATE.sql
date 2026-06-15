-- TEST stub for RULE_BBG_COMPARE_MATURITY_DATE (Snowflake).
-- Returns zero rows so ExecuteRules treats existing exceptions for this
-- rule as untouched and marks them Complete. Re-apply
-- RULE_BBG_COMPARE_MATURITY_DATE.sql afterwards to restore the real
-- procedure.

CREATE OR REPLACE PROCEDURE RULE_BBG_COMPARE_MATURITY_DATE(
    "ALADDIN_ID"   VARCHAR,
    "ID_BB_GLOBAL" VARCHAR
)
RETURNS TABLE(
    "ALADDIN_ID"            VARCHAR,
    "ID_BB_GLOBAL"          VARCHAR,
    "BBG_MATURITY_DATE"     VARCHAR,
    "ALADDIN_MATURITY_DATE" VARCHAR,
    "ISSUE_DESCRIPTION"     VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT NULL::VARCHAR AS "ALADDIN_ID",
               NULL::VARCHAR AS "ID_BB_GLOBAL",
               NULL::VARCHAR AS "BBG_MATURITY_DATE",
               NULL::VARCHAR AS "ALADDIN_MATURITY_DATE",
               NULL::VARCHAR AS "ISSUE_DESCRIPTION"
        WHERE FALSE
    );
    RETURN TABLE(res);
END;
$$;
