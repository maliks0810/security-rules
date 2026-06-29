CREATE OR REPLACE PROCEDURE RECON_BBG_COMPARE(
    P_ALADDIN_ID   VARCHAR,
    P_ID_BB_GLOBAL VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"         VARCHAR,
    "ALADDIN_ID"        VARCHAR,
    "ID_BB_GLOBAL"      VARCHAR,
    "BBG_VALUE"         VARCHAR,
    "ALADDIN_VALUE"     VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RULE_ID"           NUMBER
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    -- When the caller supplies (P_ALADDIN_ID, P_ID_BB_GLOBAL) we reflect
    -- that pair per BBG-compare rule. When both are NULL/empty (the "run
    -- for all assets" path) we emit a fixed demo set of three assets so
    -- the pipeline still produces visible exceptions for testing.
    -- RULE_ID is resolved from RULE by RULE_NAME so the Go ExecuteRule
    -- layer can tag each emitted exception with its rule.
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
        ),
        assets AS (
            SELECT :P_ALADDIN_ID::VARCHAR   AS aladdin_id,
                   :P_ID_BB_GLOBAL::VARCHAR AS id_bb_global
             WHERE :P_ALADDIN_ID IS NOT NULL AND :P_ALADDIN_ID <> ''
            UNION ALL
            SELECT column1::VARCHAR, column2::VARCHAR
            FROM (VALUES
                ('73316NAC9', 'BBG000B7NKY4'),
                ('45661EAB0', 'BBG000B06N81'),
                ('466317AU8', 'BBG016XZK9N4')
            )
            WHERE :P_ALADDIN_ID IS NULL OR :P_ALADDIN_ID = ''
        )
        SELECT src.rule_name      AS "RULE_NAME",
               assets.aladdin_id  AS "ALADDIN_ID",
               assets.id_bb_global AS "ID_BB_GLOBAL",
               src.bbg_value      AS "BBG_VALUE",
               src.aladdin_value  AS "ALADDIN_VALUE",
               src.issue_description AS "ISSUE_DESCRIPTION",
               r."RULE_ID"        AS "RULE_ID"
        FROM assets
        CROSS JOIN src
        JOIN "RULE" r ON r."RULE_NAME" = src.rule_name
    );
    RETURN TABLE(res);
END;
$$;
