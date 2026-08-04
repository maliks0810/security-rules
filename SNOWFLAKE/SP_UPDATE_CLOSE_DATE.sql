-- Stamps CLOSE_DATE = today on any EXCEPTION_HIST row that represents
-- a (RULE_ID, ASSET_ID) exception that no longer surfaces in the live
-- EXCEPTION table. Intended to run after ExecuteRules has finished
-- archive → insert → inherit → revert, so EXCEPTION holds only the
-- current run's fresh rows and EXCEPTION_HIST holds every prior batch.
--
-- "Previous batch_id" per (RULE_ID, ASSET_ID) resolves via the standard
-- max (EXCEPTION_DATE, BATCH_ID) ordering used elsewhere: same day's
-- later batches win when today has archives; falls through to
-- yesterday's final batch on the first run of a fresh day.
--
-- Idempotent: rows already stamped (CLOSE_DATE IS NOT NULL) are
-- skipped, so re-running the SP on subsequent days doesn't advance the
-- date. Each distinct closure event corresponds to a distinct hist row
-- and gets its own CLOSE_DATE stamped exactly once.
--
-- Returns the number of hist rows stamped.

CREATE OR REPLACE PROCEDURE SP_UPDATE_CLOSE_DATE()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    today    DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION_HIST" h
       SET "CLOSE_DATE" = :today
      FROM (
          SELECT "EXCEPTION_ID", "RULE_ID", "ASSET_ID"
            FROM (
                SELECT "EXCEPTION_ID", "RULE_ID", "ASSET_ID",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
            )
           WHERE rn = 1
      ) latest
     WHERE h."EXCEPTION_ID" = latest."EXCEPTION_ID"
       AND h."CLOSE_DATE"   IS NULL
       AND NOT EXISTS (
           SELECT 1
             FROM "EXCEPTION" e
            WHERE e."RULE_ID"  = latest."RULE_ID"
              AND e."ASSET_ID" = latest."ASSET_ID"
       );
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
