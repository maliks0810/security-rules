DROP FUNCTION IF EXISTS public."LIST_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying, text);

-- Returns one row per RULE_CATALOG. RULE_COMMAND is the catalog's
-- RULE_CATALOG_SOURCE SQL; when the Go ExecuteRule layer runs it, the
-- result set is expected to include a RULE_ID column per row that
-- identifies which RULE produced the row. ENVIRONMENT is the catalog's
-- RULE_CATALOG_CONNECTION value. P_PROCESS_TYPE is accepted for caller
-- compatibility but ignored — RULE_CATALOG has no process-type column.
CREATE OR REPLACE FUNCTION public."GET_RULES"(
    "PROCESS_TYPE" character varying,
    p_rule_catalog text DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"   numeric,
    "RULE_CATALOG_NAME" character varying,
    "RULE_COMMAND"      character varying,
    "ENVIRONMENT"       character varying
)
LANGUAGE sql
AS $$
    SELECT rc."RULE_CATALOG_ID"::numeric                       AS "RULE_CATALOG_ID",
           rc."NAME"::character varying                        AS "RULE_CATALOG_NAME",
           rc."RULE_CATALOG_SOURCE"::character varying         AS "RULE_COMMAND",
           rc."RULE_CATALOG_CONNECTION"::character varying     AS "ENVIRONMENT"
    FROM public."RULE_CATALOG" rc
    WHERE (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME" = p_rule_catalog);
$$;
