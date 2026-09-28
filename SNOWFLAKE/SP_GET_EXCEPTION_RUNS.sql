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

CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_RUNS(
    P_RULE_GROUP   VARCHAR DEFAULT NULL,
    P_RULE_CATALOG VARCHAR DEFAULT NULL,
    P_RULE_NAME    VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    "EXCEPTION_DATE" DATE,
    "BATCH_ID"       NUMBER,
    "EXCEPTION_TIME" TIMESTAMP_NTZ
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH live_date AS (
            SELECT MAX("EXCEPTION_DATE") AS d FROM "EXCEPTION"
        )
        SELECT e."EXCEPTION_DATE"      AS "EXCEPTION_DATE",
               NULL::NUMBER            AS "BATCH_ID",
               MAX(e."EXCEPTION_TIME") AS "EXCEPTION_TIME"
          FROM "EXCEPTION" e
          LEFT JOIN "RULE"         r  ON r."RULE_ID"          = e."RULE_ID"
          LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
         WHERE e."EXCEPTION_DATE" = (SELECT d FROM live_date)
           AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
           AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME"     = :P_RULE_CATALOG)
           AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
         GROUP BY e."EXCEPTION_DATE"
        UNION ALL
        SELECT h."EXCEPTION_DATE"      AS "EXCEPTION_DATE",
               h."BATCH_ID"            AS "BATCH_ID",
               MAX(h."EXCEPTION_TIME") AS "EXCEPTION_TIME"
          FROM "EXCEPTION_HIST" h
          LEFT JOIN "RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
          LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
         WHERE h."EXCEPTION_DATE" IS NOT NULL
           AND h."BATCH_ID"       IS NOT NULL
           AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
           AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME"     = :P_RULE_CATALOG)
           AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
         GROUP BY h."EXCEPTION_DATE", h."BATCH_ID"
        ORDER BY "EXCEPTION_DATE" DESC, "BATCH_ID" DESC NULLS FIRST
    );
    RETURN TABLE(res);
END;
$$;
