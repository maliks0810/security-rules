-- Postgres conversion of RULE_COMPARE_REGISTRATION.sql (Snowflake).
-- The source views (common.BBG_INTRADAY_SECURITY_VW, tdc.SECURITY_CURRENT_VW)
-- come from Snowflake and need local equivalents (or stubs) before this
-- function can be executed here. The original Snowflake body also has the
-- hardcoded ID_BB_GLOBAL/ALADDIN_ID filters that look like leftover debug
-- values; this conversion uses the function parameters instead.

DROP FUNCTION IF EXISTS public."RULE_COMPARE_REGISTRATION"(varchar, varchar);

CREATE OR REPLACE FUNCTION public."RULE_COMPARE_REGISTRATION"(
    "ALADDIN_ID"   varchar(15),
    "ID_BB_GLOBAL" varchar(15)
)
RETURNS TABLE(
    "ALADDIN_ID"           varchar,
    "ID_BB_GLOBAL"         varchar,
    "BBG_REGISTRATION"     varchar,
    "ALADDIN_REGISTRATION" varchar,
    "ISSUE_DESCRIPTION"    varchar
)
LANGUAGE sql
AS $$
    WITH BBG AS (
        SELECT
            bb."HDRID",
            bb."ID_BB_GLOBAL",
            CASE
                WHEN bb."Z144A_FLAG"            = 'Y' AND bb."IS_REG_S" = 'Y' THEN 'Dual 144a|Reg-S'
                WHEN bb."Z144A_FLAG"            = 'Y'                          THEN '144a'
                WHEN bb."IS_REG_S"              = 'Y'                          THEN 'Reg-S'
                WHEN bb."REGULATION_D_INDICATOR" = 'Y'                          THEN 'Reg-D'
                WHEN bb."Z144A_REG_RIGHTS"      = 'Y'                          THEN 'Dual 144a|Reg-S'
                ELSE 'Public'
            END AS "BBG_REGISTRATION"
        FROM common."BBG_INTRADAY_SECURITY_VW" bb
        WHERE bb."ID_BB_GLOBAL" = $2
          AND bb."HDRID" = 75
    ),
    ALADDIN AS (
        SELECT
            "ALADDIN_ID",
            "REGISTRATION" AS "ALADDIN_REGISTRATION"
        FROM tdc."SECURITY_CURRENT_VW"
        WHERE "ALADDIN_ID" = $1
    )
    SELECT
        a."ALADDIN_ID"::varchar,
        b."ID_BB_GLOBAL"::varchar,
        b."BBG_REGISTRATION"::varchar,
        a."ALADDIN_REGISTRATION"::varchar,
        ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
         a."ALADDIN_REGISTRATION" || ' BBG Registration:' ||
         b."BBG_REGISTRATION")::varchar AS "ISSUE_DESCRIPTION"
    FROM BBG b
    CROSS JOIN ALADDIN a;
$$;
