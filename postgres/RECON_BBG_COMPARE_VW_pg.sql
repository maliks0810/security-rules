-- Dummy stand-in for the Snowflake COMMON.RECON_BBG_COMPARE_VW view used
-- by the Bloomberg-compare rules. Hardcodes one row per rule (maturity
-- and registration) so the full ExecuteRules pipeline can be demoed
-- end-to-end. The RULE_NAME column is read by ExecuteRule to route
-- each row to its matching rule.

DROP VIEW IF EXISTS public."RECON_BBG_COMPARE_VW";

CREATE VIEW public."RECON_BBG_COMPARE_VW" AS
SELECT
    'RULE_DM_BBG_MATURITY_DATE'::varchar AS "RULE_NAME",
    '38384LJ83'::varchar                 AS "ALADDIN_ID",
    'BBG01Z2F2QF9'::varchar              AS "ID_BB_GLOBAL",
    '4/18/2029'::varchar                 AS "BBG_VALUE",
    '5/15/2029'::varchar                 AS "ALADDIN_VALUE",
    ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
        '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::varchar
                                         AS "ISSUE_DESCRIPTION"
UNION ALL
SELECT
    'RULE_DM_BBG_REGISTRATION'::varchar AS "RULE_NAME",
    'BDL36EUA0'::varchar                AS "ALADDIN_ID",
    'BBG00G6M2LZ2'::varchar             AS "ID_BB_GLOBAL",
    'Reg S'::varchar                    AS "BBG_VALUE",
    '144A'::varchar                     AS "ALADDIN_VALUE",
    ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
        '144A' || ' BBG Registration:' || 'Reg S')::varchar
                                        AS "ISSUE_DESCRIPTION";
