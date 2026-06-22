DROP FUNCTION IF EXISTS public."GET_RULE_NAMES"(text);

-- Returns individual RULE_NAMEs belonging to a given catalog. Used by the
-- tcw-dqm tree view (Group -> Catalog -> Rule) since GET_RULES now returns
-- one row per catalog rather than one row per rule.
CREATE OR REPLACE FUNCTION public."GET_RULE_NAMES"(
    p_rule_catalog text
)
RETURNS TABLE("RULE_NAME" character varying)
LANGUAGE sql
AS $$
    SELECT r."RULE_NAME"
    FROM public."RULE" r
    JOIN public."RULE_CATALOG" rc
      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
    WHERE rc."NAME" = p_rule_catalog
    ORDER BY r."RULE_NAME" ASC;
$$;
