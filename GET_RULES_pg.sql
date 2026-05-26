DROP FUNCTION IF EXISTS public."LIST_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying);
DROP FUNCTION IF EXISTS public."GET_RULES"(character varying, text);

CREATE OR REPLACE FUNCTION public."GET_RULES"(
    "PROCESS_TYPE" character varying,
    p_rule_type    text DEFAULT NULL
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
           r."RULE_COMMAND",
           r."ENVIRONMENT"
    FROM public."RULE" r
    JOIN public."RULE_TYPE" rt
      ON rt."RULE_TYPE_ID" = r."RULE_TYPE_ID"
    WHERE (p_rule_type IS NULL OR p_rule_type = 'All' OR rt."NAME" = p_rule_type);
$$;
