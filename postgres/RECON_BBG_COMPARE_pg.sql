-- RECON_BBG_COMPARE: SP shape of the deprecated RECON_BBG_COMPARE_VW.
-- Takes (ALADDIN_ID, ID_BB_GLOBAL) and reflects them back per row.
-- Returns one row per BBG-compare rule with RULE_ID resolved from the
-- RULE table by RULE_NAME so the Go ExecuteRule layer can tag each
-- emitted exception with its rule.
--
-- Params are renamed with p_ prefix to avoid collision with output columns.

DROP FUNCTION IF EXISTS public."RECON_BBG_COMPARE"(varchar, varchar);

CREATE OR REPLACE FUNCTION public."RECON_BBG_COMPARE"(
    p_aladdin_id   varchar(15),
    p_id_bb_global varchar(15)
)
RETURNS TABLE(
    "RULE_ID"           numeric,
    "RULE_NAME"         varchar,
    "ALADDIN_ID"        varchar,
    "ID_BB_GLOBAL"      varchar,
    "BBG_VALUE"         varchar,
    "ALADDIN_VALUE"     varchar,
    "ISSUE_DESCRIPTION" varchar
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
    )
    SELECT r."RULE_ID"::numeric           AS "RULE_ID",
           src.rule_name                  AS "RULE_NAME",
           p_aladdin_id::varchar          AS "ALADDIN_ID",
           p_id_bb_global::varchar        AS "ID_BB_GLOBAL",
           src.bbg_value                  AS "BBG_VALUE",
           src.aladdin_value              AS "ALADDIN_VALUE",
           src.issue_description          AS "ISSUE_DESCRIPTION"
    FROM src
    JOIN public."RULE" r ON r."RULE_NAME" = src.rule_name;
$$;
