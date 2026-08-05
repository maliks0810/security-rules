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
    today            DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    disappeared      NUMBER := 0;
    accept_research  NUMBER := 0;
    reopened_new     NUMBER := 0;
BEGIN
    -- Pass 1: (RULE_ID, ASSET_ID) present in HIST but no longer in EXCEPTION.
    -- Stamp CLOSE_DATE on that combo's latest hist row.
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
    disappeared := SQLROWCOUNT;

    -- Pass 2: live EXCEPTION rows currently in status 'Accept' or
    -- 'Research' whose CLOSE_DATE is NULL. Belt-and-suspenders alongside
    -- SP_UPDATE_EXCEPTION_STATUS / SP_UPDATE_BULK_STATUS (which stamp
    -- CLOSE_DATE on the transition itself). Catches inherited-status
    -- rows — SP_INHERIT_EXCEPTION_STATUSES pulls STATUS_ID forward from
    -- hist without touching CLOSE_DATE — and any row that took the
    -- transition before CLOSE_DATE existed as a column. Idempotent
    -- through the IS NULL guard.
    UPDATE "EXCEPTION" e
       SET "CLOSE_DATE" = :today
     WHERE e."CLOSE_DATE" IS NULL
       AND e."STATUS_ID" IN (
           SELECT "EXCEPTION_STATUS_ID"
             FROM "EXCEPTION_STATUS"
            WHERE "NAME" IN ('Accept', 'Research')
       );
    accept_research := SQLROWCOUNT;

    -- Pass 3: live EXCEPTION rows currently back in status 'New'
    -- (reopened via operator flip, SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_
    -- DIFFERENCES, SP_EXPIRE_SUPPRESS_DATES, inherited-New, …) whose
    -- CLOSE_DATE is still populated from a previous Accept / Research
    -- run. Clear it so the grid doesn't show a New row carrying a
    -- stale close date. Idempotent through the IS NOT NULL guard.
    UPDATE "EXCEPTION" e
       SET "CLOSE_DATE" = NULL
     WHERE e."CLOSE_DATE" IS NOT NULL
       AND e."STATUS_ID" = 1;
    reopened_new := SQLROWCOUNT;

    RETURN disappeared + accept_research + reopened_new;
END;
$$;
