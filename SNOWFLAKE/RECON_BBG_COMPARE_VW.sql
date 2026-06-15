CREATE OR REPLACE VIEW RECON_BBG_COMPARE_VW AS
SELECT
    'RULE_DM_BBG_MATURITY_DATE'::VARCHAR AS "RULE_NAME",
    '38384LJ83'::VARCHAR                 AS "ALADDIN_ID",
    'BBG01Z2F2QF9'::VARCHAR              AS "ID_BB_GLOBAL",
    '4/18/2029'::VARCHAR                 AS "BBG_VALUE",
    '5/15/2029'::VARCHAR                 AS "ALADDIN_VALUE",
    ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
        '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::VARCHAR
                                         AS "ISSUE_DESCRIPTION"
UNION ALL
SELECT
    'RULE_DM_BBG_REGISTRATION'::VARCHAR AS "RULE_NAME",
    'BDL36EUA0'::VARCHAR                AS "ALADDIN_ID",
    'BBG00G6M2LZ2'::VARCHAR             AS "ID_BB_GLOBAL",
    'Reg S'::VARCHAR                    AS "BBG_VALUE",
    '144A'::VARCHAR                     AS "ALADDIN_VALUE",
    ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
        '144A' || ' BBG Registration:' || 'Reg S')::VARCHAR
                                        AS "ISSUE_DESCRIPTION";
