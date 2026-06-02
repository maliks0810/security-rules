DROP FUNCTION IF EXISTS public."GET_RULE_TYPES"(text);

CREATE OR REPLACE FUNCTION public."GET_RULE_TYPES"(
    p_rule_group text
)
RETURNS TABLE("RULE_TYPE_NAME" character varying)
LANGUAGE sql
AS $$
    SELECT rt."NAME" AS "RULE_TYPE_NAME"
    FROM public."RULE_TYPE" rt
    JOIN public."RULE_GROUP" rg
      ON rg."RULE_GROUP_ID" = rt."RULE_GROUP_ID"
    WHERE rg."NAME" = p_rule_group
    ORDER BY rt."RULE_TYPE_ID" ASC;
$$;
