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
    v_today            date    := (NOW() AT TIME ZONE 'UTC')::date;
    v_disappeared      integer := 0;
    v_accept_research  integer := 0;
BEGIN
    -- Pass 1: (RULE_ID, ASSET_ID) present in HIST but no longer in
    -- EXCEPTION. Stamp CLOSE_DATE on that combo's latest hist row.
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
    SELECT COALESCE(COUNT(*), 0)::int INTO v_disappeared FROM stamped;

    -- Pass 2: live EXCEPTION rows currently in status 'Accept' or
    -- 'Research' whose CLOSE_DATE is NULL. Belt-and-suspenders
    -- alongside SP_UPDATE_EXCEPTION_STATUS / SP_UPDATE_BULK_STATUS
    -- (which stamp CLOSE_DATE on the transition itself). Catches
    -- inherited-status rows — SP_INHERIT_EXCEPTION_STATUSES pulls
    -- STATUS_ID forward from hist without touching CLOSE_DATE — and
    -- any row that took the transition before CLOSE_DATE existed as
    -- a column. Idempotent through the IS NULL guard.
    WITH stamped_ar AS (
        UPDATE public."EXCEPTION" e
           SET "CLOSE_DATE" = v_today
         WHERE e."CLOSE_DATE" IS NULL
           AND e."STATUS_ID" IN (
               SELECT "EXCEPTION_STATUS_ID"
                 FROM public."EXCEPTION_STATUS"
                WHERE "NAME" IN ('Accept', 'Research')
           )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int INTO v_accept_research FROM stamped_ar;

    RETURN v_disappeared + v_accept_research;
END;
$$;
