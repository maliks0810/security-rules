DROP FUNCTION IF EXISTS public."LIST_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying, text);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying, text, text);
DROP FUNCTION IF EXISTS public."GET_RULES"(text, text);

-- Returns one row per RULE_CATALOG (see SNOWFLAKE/GET_RULES.sql for the
-- full contract). Filter behavior:
--   p_rule_type = 'CATALOG' or 'RULE' → p_rule_name matches RULE_CATALOG.NAME.
--   p_rule_type = 'GROUP'             → p_rule_name matches RULE_GROUP.NAME.
--   p_rule_name NULL / empty / 'All'  → no filter; return every catalog.
CREATE OR REPLACE FUNCTION public."GET_RULES"(
    p_rule_name text DEFAULT NULL,
    p_rule_type text DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"   numeric,
    "RULE_CATALOG_NAME" character varying,
    "RULE_COMMAND"      character varying,
    "ENVIRONMENT"       character varying
)
LANGUAGE sql
AS $$
    SELECT rc."RULE_CATALOG_ID"::numeric                   AS "RULE_CATALOG_ID",
           rc."NAME"::character varying                    AS "RULE_CATALOG_NAME",
           rc."RULE_CATALOG_SOURCE"::character varying     AS "RULE_COMMAND",
           rc."RULE_CATALOG_CONNECTION"::character varying AS "ENVIRONMENT"
    FROM public."RULE_CATALOG" rc
    LEFT JOIN public."RULE_GROUP" rg
      ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
    WHERE p_rule_name IS NULL
       OR p_rule_name = ''
       OR p_rule_name = 'All'
       OR (UPPER(COALESCE(p_rule_type, 'CATALOG')) IN ('CATALOG','RULE')
             AND rc."NAME" = p_rule_name)
       OR (UPPER(p_rule_type) = 'GROUP'
             AND rg."NAME"  = p_rule_name);
$$;
