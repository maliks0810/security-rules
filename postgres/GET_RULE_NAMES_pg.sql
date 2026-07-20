DROP FUNCTION IF EXISTS public."SP_GET_RULE_NAMES"(text);

-- Returns individual RULE_NAMEs (and their RULE_DESCRIPTION) belonging
-- to a given catalog. Used by the tcw-dqm tree view to display the
-- friendlier description on the leaf when present (fall back to
-- RULE_NAME) and to populate the Exceptions header subtitle when a
-- specific rule is selected.
CREATE OR REPLACE FUNCTION public."SP_GET_RULE_NAMES"(
    p_rule_catalog text
)
RETURNS TABLE(
    "RULE_NAME"        character varying,
    "RULE_DESCRIPTION" character varying
)
LANGUAGE sql
AS $$
    SELECT r."RULE_NAME"::character varying        AS "RULE_NAME",
           r."RULE_DESCRIPTION"::character varying AS "RULE_DESCRIPTION"
    FROM public."RULE" r
    JOIN public."RULE_CATALOG" rc
      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
    WHERE rc."NAME" = p_rule_catalog
    ORDER BY r."RULE_NAME" ASC;
$$;
