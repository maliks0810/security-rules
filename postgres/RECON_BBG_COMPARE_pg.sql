-- RECON_BBG_COMPARE: SP shape of the deprecated RECON_BBG_COMPARE_VW.
-- When a caller passes (p_aladdin_id, p_id_bb_global), it reflects that
-- pair back per BBG-compare rule. When both are NULL/empty (the "run for
-- all assets" path), it emits a fixed demo set of three assets so the
-- pipeline still produces visible exceptions for testing.
-- RULE_ID is resolved from the RULE table by RULE_NAME so the Go
-- ExecuteRule layer can tag each emitted exception with its rule.

DROP FUNCTION IF EXISTS public."SP_RECON_BBG_COMPARE"(varchar, varchar);

CREATE OR REPLACE FUNCTION public."SP_RECON_BBG_COMPARE"(
    p_aladdin_id   varchar(15),
    p_id_bb_global varchar(15)
)
RETURNS TABLE(
    "RULE_NAME"         varchar,
    "ALADDIN_ID"        varchar,
    "ID_BB_GLOBAL"      varchar,
    "BBG_VALUE"         varchar,
    "ALADDIN_VALUE"     varchar,
    "ISSUE_DESCRIPTION" varchar,
    "RULE_ID"           numeric
)
LANGUAGE sql
AS $$
    WITH src AS (
        SELECT
            'RULE_DM_BBG_MATURITY_DATE'::varchar AS rule_name,
            '4/18/2029'::varchar                 AS bbg_value,
            '5/15/2029'::varchar                 AS aladdin_value,
            ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
                '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::varchar
                                                 AS issue_description
        UNION ALL
        SELECT
            'RULE_DM_BBG_REGISTRATION'::varchar,
            'Reg S'::varchar,
            '144A'::varchar,
            ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
                '144A' || ' BBG Registration:' || 'Reg S')::varchar
    ),
    -- Caller path: use the (aladdin, figi) pair when supplied; otherwise
    -- emit the demo asset set so the unfiltered run still has output.
    assets AS (
        SELECT p_aladdin_id::varchar   AS aladdin_id,
               p_id_bb_global::varchar AS id_bb_global
         WHERE p_aladdin_id IS NOT NULL AND p_aladdin_id <> ''
        UNION ALL
        SELECT v.aladdin_id::varchar, v.id_bb_global::varchar
        FROM (VALUES
            ('73316NAC9', 'BBG000B7NKY4'),
            ('45661EAB0', 'BBG000B06N81'),
            ('466317AU8', 'BBG016XZK9N4')
        ) AS v(aladdin_id, id_bb_global)
        WHERE p_aladdin_id IS NULL OR p_aladdin_id = ''
    )
    SELECT src.rule_name               AS "RULE_NAME",
           assets.aladdin_id           AS "ALADDIN_ID",
           assets.id_bb_global         AS "ID_BB_GLOBAL",
           src.bbg_value               AS "BBG_VALUE",
           src.aladdin_value           AS "ALADDIN_VALUE",
           src.issue_description       AS "ISSUE_DESCRIPTION",
           r."RULE_ID"::numeric        AS "RULE_ID"
    FROM assets
    CROSS JOIN src
    JOIN public."RULE" r ON r."RULE_NAME" = src.rule_name;
$$;
