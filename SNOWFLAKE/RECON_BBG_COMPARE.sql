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
    "ISSUE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT
            'RULE_DM_BBG_MATURITY_DATE'::VARCHAR AS "RULE_NAME",
            :P_ALADDIN_ID::VARCHAR               AS "ALADDIN_ID",
            :P_ID_BB_GLOBAL::VARCHAR             AS "ID_BB_GLOBAL",
            '4/18/2029'::VARCHAR                 AS "BBG_VALUE",
            '5/15/2029'::VARCHAR                 AS "ALADDIN_VALUE",
            ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
                '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::VARCHAR
                                                 AS "ISSUE_DESCRIPTION"
        UNION ALL
        SELECT
            'RULE_DM_BBG_REGISTRATION'::VARCHAR,
            :P_ALADDIN_ID::VARCHAR,
            :P_ID_BB_GLOBAL::VARCHAR,
            'Reg S'::VARCHAR,
            '144A'::VARCHAR,
            ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
                '144A' || ' BBG Registration:' || 'Reg S')::VARCHAR
    );
    RETURN TABLE(res);
END;
$$;
