DROP FUNCTION IF EXISTS public."SP_GET_RULES_FOR_GROUP"(text);

-- Returns one row per active RULE under the given RULE_GROUP,
-- projected as (rule_name, catalog_name, description). Postgres
-- mirror of SNOWFLAKE/SP_GET_RULES_FOR_GROUP.sql. Collapses the
-- catalog + rule-names N+1 fanout the LHS tree used to do into a
-- single call.
CREATE OR REPLACE FUNCTION public."SP_GET_RULES_FOR_GROUP"(
    p_rule_group text
)
RETURNS TABLE(
    "RULE_NAME"        character varying,
    "CATALOG_NAME"     character varying,
    "RULE_DESCRIPTION" character varying
)
LANGUAGE sql
AS $$
    SELECT r."RULE_NAME"::character varying        AS "RULE_NAME",
           rc."NAME"::character varying            AS "CATALOG_NAME",
           r."RULE_DESCRIPTION"::character varying AS "RULE_DESCRIPTION"
    FROM public."RULE" r
    JOIN public."RULE_CATALOG" rc
      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
    JOIN public."RULE_GROUP"   rg
      ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
    WHERE rg."NAME" = p_rule_group
      AND r."IS_ACTIVE" = 1
    ORDER BY rc."NAME" ASC, r."RULE_NAME" ASC;
$$;
