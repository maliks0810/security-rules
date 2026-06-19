-- RECON_BBG_COMPARE: SP shape of RECON_BBG_COMPARE_VW. Takes the same
-- (ALADDIN_ID, ID_BB_GLOBAL) parameters as RULE_BBG_COMPARE_MATURITY_DATE
-- and reflects them back in the ALADDIN_ID / ID_BB_GLOBAL columns of
-- both the maturity-date and registration rows. Params are renamed with
-- p_ prefix to avoid collision with the same-named output columns.

DROP FUNCTION IF EXISTS public."RECON_BBG_COMPARE"(varchar, varchar);

CREATE OR REPLACE FUNCTION public."RECON_BBG_COMPARE"(
    p_aladdin_id   varchar(15),
    p_id_bb_global varchar(15)
)
RETURNS TABLE(
    "RULE_NAME"         varchar,
    "ALADDIN_ID"        varchar,
    "ID_BB_GLOBAL"      varchar,
    "BBG_VALUE"         varchar,
    "ALADDIN_VALUE"     varchar,
    "ISSUE_DESCRIPTION" varchar
)
LANGUAGE sql
AS $$
    SELECT
        'RULE_DM_BBG_MATURITY_DATE'::varchar AS "RULE_NAME",
        p_aladdin_id::varchar                AS "ALADDIN_ID",
        p_id_bb_global::varchar              AS "ID_BB_GLOBAL",
        '4/18/2029'::varchar                 AS "BBG_VALUE",
        '5/15/2029'::varchar                 AS "ALADDIN_VALUE",
        ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
            '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::varchar
                                             AS "ISSUE_DESCRIPTION"
    UNION ALL
    SELECT
        'RULE_DM_BBG_REGISTRATION'::varchar,
        p_aladdin_id::varchar,
        p_id_bb_global::varchar,
        'Reg S'::varchar,
        '144A'::varchar,
        ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
            '144A' || ' BBG Registration:' || 'Reg S')::varchar;
$$;
