DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_RUNS"(text, text, text);

-- One row per rule run the "Exceptions Date" dropdown can offer for a
-- rule group / catalog / rule picked on the LHS tree, most recent first:
--   * the live run: EXCEPTION rows on the live date (MAX(EXCEPTION_DATE)
--     across the whole table, which is what the grid's current view
--     reads), BATCH_ID NULL. Absent when the scope has no live rows.
--   * one row per (EXCEPTION_DATE, BATCH_ID) in EXCEPTION_HIST.
-- EXCEPTION_TIME is the latest EXCEPTION_TIME among the run's rows, so
-- the dropdown can tell apart several runs on the same day.
--
-- NULL or 'All' leaves a scope level unfiltered (same convention as
-- SP_GET_EXCEPTIONS_HIST).
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_RUNS"(
    p_rule_group   text DEFAULT NULL,
    p_rule_catalog text DEFAULT NULL,
    p_rule_name    text DEFAULT NULL
)
RETURNS TABLE(
    "EXCEPTION_DATE" date,
    "BATCH_ID"       bigint,
    "EXCEPTION_TIME" timestamp without time zone
)
LANGUAGE sql
AS $$
    WITH live_date AS (
        SELECT MAX("EXCEPTION_DATE") AS d FROM public."EXCEPTION"
    )
    SELECT e."EXCEPTION_DATE"      AS "EXCEPTION_DATE",
           NULL::bigint            AS "BATCH_ID",
           MAX(e."EXCEPTION_TIME") AS "EXCEPTION_TIME"
      FROM public."EXCEPTION" e
      LEFT JOIN public."RULE"         r  ON r."RULE_ID"          = e."RULE_ID"
      LEFT JOIN public."RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
      LEFT JOIN public."RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
     WHERE e."EXCEPTION_DATE" = (SELECT d FROM live_date)
       AND (p_rule_group   IS NULL OR p_rule_group   = 'All' OR rg."NAME"     = p_rule_group)
       AND (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME"     = p_rule_catalog)
       AND (p_rule_name    IS NULL OR p_rule_name    = 'All' OR r."RULE_NAME" = p_rule_name)
     GROUP BY e."EXCEPTION_DATE"
    UNION ALL
    SELECT h."EXCEPTION_DATE"      AS "EXCEPTION_DATE",
           h."BATCH_ID"            AS "BATCH_ID",
           MAX(h."EXCEPTION_TIME") AS "EXCEPTION_TIME"
      FROM public."EXCEPTION_HIST" h
      LEFT JOIN public."RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
      LEFT JOIN public."RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
      LEFT JOIN public."RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
     WHERE h."EXCEPTION_DATE" IS NOT NULL
       AND h."BATCH_ID"       IS NOT NULL
       AND (p_rule_group   IS NULL OR p_rule_group   = 'All' OR rg."NAME"     = p_rule_group)
       AND (p_rule_catalog IS NULL OR p_rule_catalog = 'All' OR rc."NAME"     = p_rule_catalog)
       AND (p_rule_name    IS NULL OR p_rule_name    = 'All' OR r."RULE_NAME" = p_rule_name)
     GROUP BY h."EXCEPTION_DATE", h."BATCH_ID"
    ORDER BY "EXCEPTION_DATE" DESC, "BATCH_ID" DESC NULLS FIRST;
$$;
