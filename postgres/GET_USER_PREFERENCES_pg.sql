DROP FUNCTION IF EXISTS public."SP_GET_USER_PREFERENCES"(text, text, text);

-- Returns the saved COLUMN_ORDER for the (user, rule_group,
-- rule_catalog) scope. Postgres mirror of SNOWFLAKE/
-- SP_GET_USER_PREFERENCES.sql. Zero rows means "no saved layout —
-- fall back to canonical default order". p_rule_catalog null / ''
-- matches the row where RULE_CATALOG_ID IS NULL (group-root scope).
CREATE OR REPLACE FUNCTION public."SP_GET_USER_PREFERENCES"(
    p_user          text,
    p_rule_group    text,
    p_rule_catalog  text
)
RETURNS TABLE(
    "COLUMN_ORDER" varchar
)
LANGUAGE sql
AS $$
    SELECT up."COLUMN_ORDER"
    FROM public."USER_PREFERENCES" up
    JOIN public."DM_USER"    du ON du."ID"            = up."DM_USER_ID"
    JOIN public."RULE_GROUP" rg ON rg."RULE_GROUP_ID" = up."RULE_GROUP_ID"
    LEFT JOIN public."RULE_CATALOG" rc
           ON rc."RULE_CATALOG_ID" = up."RULE_CATALOG_ID"
    WHERE du."USER" = p_user
      AND rg."NAME" = p_rule_group
      AND rc."NAME" IS NOT DISTINCT FROM
          CASE
              WHEN p_rule_catalog IS NULL OR p_rule_catalog = ''
                  THEN NULL
              ELSE p_rule_catalog
          END
    LIMIT 1;
$$;
