DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_HIST_DATES"();
DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_HIST_DATES"(text, text, text);

-- Returns every distinct EXCEPTION_DATE the DQM Date dropdown should
-- offer, most recent first:
--   * the single MAX EXCEPTION_DATE from the live EXCEPTION table
--     (the "current" pick for the top of the dropdown)
--   * every distinct EXCEPTION_DATE from EXCEPTION_HIST
-- Union deduplicates when the live max also appears in HIST. No
-- CURRENT_DATE / UTC math: the labels are driven entirely by what's
-- actually in the two tables, so the frontend doesn't drift from
-- server state when local vs UTC disagree.
--
-- p_rule_group / p_rule_catalog / p_rule_name scope both halves to the
-- rule group, catalog or rule picked on the LHS tree, so the dropdown
-- only offers days on which that scope actually has exceptions. NULL or
-- 'All' means no filter on that level (same convention as
-- SP_GET_EXCEPTIONS_HIST).
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_HIST_DATES"(
    p_rule_group   text DEFAULT NULL,
    p_rule_catalog text DEFAULT NULL,
    p_rule_name    text DEFAULT NULL
)
RETURNS TABLE("EXCEPTION_DATE" date)
LANGUAGE sql
AS $$
    SELECT d AS "EXCEPTION_DATE"
    FROM (
        SELECT MAX(e."EXCEPTION_DATE") AS d
          FROM public."EXCEPTION" e
          LEFT JOIN public."RULE"         r  ON r."RULE_ID"          = e."RULE_ID"
          LEFT JOIN public."RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN public."RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
         WHERE e."EXCEPTION_DATE" IS NOT NULL
           AND (p_rule_group   IS NULL OR p_rule_group   = 'All' OR rg."NAME"     = p_rule_group)
           AND (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME"     = p_rule_catalog)
           AND (p_rule_name    IS NULL OR p_rule_name    = 'All' OR r."RULE_NAME" = p_rule_name)
        UNION
        SELECT DISTINCT h."EXCEPTION_DATE" AS d
          FROM public."EXCEPTION_HIST" h
          LEFT JOIN public."RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
          LEFT JOIN public."RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN public."RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
         WHERE h."EXCEPTION_DATE" IS NOT NULL
           AND (p_rule_group   IS NULL OR p_rule_group   = 'All' OR rg."NAME"     = p_rule_group)
           AND (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME"     = p_rule_catalog)
           AND (p_rule_name    IS NULL OR p_rule_name    = 'All' OR r."RULE_NAME" = p_rule_name)
    ) x
    WHERE d IS NOT NULL
    ORDER BY d DESC;
$$;
