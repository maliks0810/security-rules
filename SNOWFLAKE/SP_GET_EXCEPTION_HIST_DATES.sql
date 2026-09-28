-- Distinct EXCEPTION_DATEs for the "Exceptions Date" dropdown in the LHS
-- sidebar, most recent first:
--   * the MAX EXCEPTION_DATE from the live EXCEPTION table
--   * every distinct EXCEPTION_DATE from EXCEPTION_HIST
-- One entry per day regardless of how many BATCH_IDs that day accumulated.
--
-- P_RULE_GROUP / P_RULE_CATALOG / P_RULE_NAME scope both halves to the
-- rule group, catalog or rule picked on the LHS tree, so the dropdown
-- only offers days on which that scope actually has exceptions. NULL or
-- 'All' means no filter on that level (same convention as
-- SP_GET_EXCEPTIONS_HIST).
--
-- The old zero-argument version is dropped in 200_UPDATE_ADHOC.sql.

CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_HIST_DATES(
    P_RULE_GROUP   VARCHAR DEFAULT NULL,
    P_RULE_CATALOG VARCHAR DEFAULT NULL,
    P_RULE_NAME    VARCHAR DEFAULT NULL
)
RETURNS TABLE("EXCEPTION_DATE" DATE)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT d AS "EXCEPTION_DATE"
        FROM (
            SELECT MAX(e."EXCEPTION_DATE") AS d
              FROM "EXCEPTION" e
              LEFT JOIN "RULE"         r  ON r."RULE_ID"          = e."RULE_ID"
              LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
             WHERE e."EXCEPTION_DATE" IS NOT NULL
               AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"      = :P_RULE_GROUP)
               AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME"      = :P_RULE_CATALOG)
               AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME"  = :P_RULE_NAME)
            UNION
            SELECT DISTINCT h."EXCEPTION_DATE" AS d
              FROM "EXCEPTION_HIST" h
              LEFT JOIN "RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
              LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
             WHERE h."EXCEPTION_DATE" IS NOT NULL
               AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"      = :P_RULE_GROUP)
               AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME"      = :P_RULE_CATALOG)
               AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME"  = :P_RULE_NAME)
        ) x
        WHERE d IS NOT NULL
        ORDER BY d DESC
    );
    RETURN TABLE(res);
END;
$$;
