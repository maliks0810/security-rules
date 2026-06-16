DROP FUNCTION IF EXISTS public."LIST_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying, text);

-- RULE_COMMAND now comes from RULE_CATALOG.RULE_CATALOG_SOURCE (raw SQL).
-- The Go ExecuteRule layer executes the returned string verbatim.
CREATE OR REPLACE FUNCTION public."GET_RULES"(
    "PROCESS_TYPE" character varying,
    p_rule_catalog text DEFAULT NULL
)
RETURNS TABLE(
    "RULE_ID"      numeric,
    "RULE_NAME"    character varying,
    "RULE_COMMAND" character varying,
    "ENVIRONMENT"  character varying
)
LANGUAGE sql
AS $$
    SELECT r."RULE_ID",
           r."RULE_NAME",
           rc."RULE_CATALOG_SOURCE"::character varying AS "RULE_COMMAND",
           NULL::character varying AS "ENVIRONMENT"
    FROM public."RULE" r
    JOIN public."RULE_CATALOG" rc
      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
    WHERE (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME" = p_rule_catalog);
$$;
