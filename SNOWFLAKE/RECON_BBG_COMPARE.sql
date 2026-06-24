CREATE OR REPLACE PROCEDURE RECON_BBG_COMPARE(
    P_ALADDIN_ID   VARCHAR,
    P_ID_BB_GLOBAL VARCHAR
)
RETURNS TABLE(
    "RULE_ID"           NUMBER,
    "RULE_NAME"         VARCHAR,
    "ALADDIN_ID"        VARCHAR,
    "ID_BB_GLOBAL"      VARCHAR,
    "BBG_VALUE"         VARCHAR,
    "ALADDIN_VALUE"     VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- RULE_ID is resolved from the RULE table by RULE_NAME so the Go
    -- ExecuteRule layer can tag each emitted exception with its rule.
    res := (
        WITH src AS (
            SELECT
                'RULE_DM_BBG_MATURITY_DATE'::VARCHAR AS rule_name,
                '4/18/2029'::VARCHAR                 AS bbg_value,
                '5/15/2029'::VARCHAR                 AS aladdin_value,
                ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
                    '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::VARCHAR
                                                     AS issue_description
            UNION ALL
            SELECT
                'RULE_DM_BBG_REGISTRATION'::VARCHAR,
                'Reg S'::VARCHAR,
                '144A'::VARCHAR,
                ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
                    '144A' || ' BBG Registration:' || 'Reg S')::VARCHAR
        )
        SELECT r."RULE_ID"             AS "RULE_ID",
               src.rule_name           AS "RULE_NAME",
               :P_ALADDIN_ID::VARCHAR  AS "ALADDIN_ID",
               :P_ID_BB_GLOBAL::VARCHAR AS "ID_BB_GLOBAL",
               src.bbg_value           AS "BBG_VALUE",
               src.aladdin_value       AS "ALADDIN_VALUE",
               src.issue_description   AS "ISSUE_DESCRIPTION"
        FROM src
        JOIN "RULE" r ON r."RULE_NAME" = src.rule_name
    );
    RETURN TABLE(res);
END;
$$;
