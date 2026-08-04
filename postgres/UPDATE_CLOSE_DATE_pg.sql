DROP FUNCTION IF EXISTS public."SP_UPDATE_CLOSE_DATE"();

-- Stamps CLOSE_DATE = today on any EXCEPTION_HIST row that represents
-- a (RULE_ID, ASSET_ID) exception that no longer surfaces in the live
-- EXCEPTION table. Intended to run after ExecuteRules has finished
-- archive → insert → inherit → revert.
--
-- "Previous batch" per (RULE_ID, ASSET_ID) resolves via max
-- (EXCEPTION_DATE, BATCH_ID) — today's later batches win when today
-- has archives; falls through to yesterday's final batch on the first
-- run of a fresh day.
--
-- Idempotent: rows already stamped (CLOSE_DATE IS NOT NULL) are
-- skipped, so re-running the SP on subsequent days doesn't advance the
-- date. Each distinct closure event corresponds to a distinct hist row
-- and gets its own CLOSE_DATE stamped exactly once.
--
-- Returns the number of hist rows stamped.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_CLOSE_DATE"()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_today    date    := (NOW() AT TIME ZONE 'UTC')::date;
    v_affected integer := 0;
BEGIN
    WITH latest AS (
        SELECT DISTINCT ON ("RULE_ID", "ASSET_ID")
               "EXCEPTION_ID", "RULE_ID", "ASSET_ID"
          FROM public."EXCEPTION_HIST"
         ORDER BY "RULE_ID", "ASSET_ID",
                  "EXCEPTION_DATE" DESC,
                  "BATCH_ID"       DESC NULLS LAST
    ),
    stamped AS (
        UPDATE public."EXCEPTION_HIST" h
           SET "CLOSE_DATE" = v_today
          FROM latest
         WHERE h."EXCEPTION_ID" = latest."EXCEPTION_ID"
           AND h."CLOSE_DATE"   IS NULL
           AND NOT EXISTS (
               SELECT 1
                 FROM public."EXCEPTION" e
                WHERE e."RULE_ID"  = latest."RULE_ID"
                  AND e."ASSET_ID" = latest."ASSET_ID"
           )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int INTO v_affected FROM stamped;
    RETURN v_affected;
END;
$$;
