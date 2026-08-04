DROP FUNCTION IF EXISTS public."SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES"();

-- Bloomberg-catalog-scoped revert workflow. For every EXCEPTION row in
-- the 'Bloomberg Compare Differences' catalog that is not currently
-- 'New', flip it back to New (with OPEN_DATE = today) when EITHER of
-- the two RESULT_DATA JSON values has drifted since the previous run:
--   * ALADDIN_VALUE differs from the last archived hist row's value, OR
--   * BBG_VALUE     differs from the last archived hist row's value.
-- "Previous run" = the EXCEPTION_HIST row with the max
-- (EXCEPTION_DATE, BATCH_ID) per (RULE_ID, ASSET_ID). Same day's later
-- batches win when today has archives; falls through to yesterday's
-- final batch on the first run of a fresh day.
--
-- Additionally, any Suppress row whose SUPPRESS_DATE has passed
-- (< today UTC) reverts to New regardless of value drift and its
-- SUPPRESS_DATE is cleared. This duplicates SP_EXPIRE_SUPPRESS_DATES's
-- global sweep but keeps the Bloomberg revert workflow self-contained
-- for callers that invoke this function directly (Rule Catalog's
-- REVERT_TO_NEW_CRITERIA).
--
-- Returns the total number of EXCEPTION rows reverted (drift + suppress
-- combined).
CREATE OR REPLACE FUNCTION public."SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES"()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_today             date      := (NOW() AT TIME ZONE 'UTC')::date;
    v_now_ts            timestamp := (NOW() AT TIME ZONE 'UTC');
    v_suppress_id       integer;
    v_drift_affected    integer   := 0;
    v_suppress_affected integer   := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID"
      INTO v_suppress_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Suppress'
     LIMIT 1;

    -- Pass 1: ALADDIN_VALUE / BBG_VALUE drift vs the latest hist row.
    WITH prev AS (
        SELECT DISTINCT ON ("RULE_ID", "ASSET_ID")
               "RULE_ID",
               "ASSET_ID",
               ("RESULT_DATA"->>'ALADDIN_VALUE') AS hist_aladdin,
               ("RESULT_DATA"->>'BBG_VALUE')     AS hist_bbg
          FROM public."EXCEPTION_HIST"
         ORDER BY "RULE_ID", "ASSET_ID",
                  "EXCEPTION_DATE" DESC,
                  "BATCH_ID"       DESC NULLS LAST
    ),
    bloomberg_rules AS (
        SELECT r."RULE_ID"
          FROM public."RULE" r
          JOIN public."RULE_CATALOG" rc
            ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
         WHERE rc."NAME" = 'Bloomberg Compare Differences'
    ),
    drift_upd AS (
        UPDATE public."EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "OPEN_DATE"     = v_today,
               "SUPPRESS_DATE" = NULL,
               "MODIFIED_DATE" = v_now_ts,
               "MODIFIED_BY"   = 'system'
          FROM prev
         WHERE e."RULE_ID"  = prev."RULE_ID"
           AND e."ASSET_ID" = prev."ASSET_ID"
           AND e."STATUS_ID" <> 1
           AND e."RULE_ID" IN (SELECT "RULE_ID" FROM bloomberg_rules)
           AND ( (e."RESULT_DATA"->>'ALADDIN_VALUE') IS DISTINCT FROM prev.hist_aladdin
              OR (e."RESULT_DATA"->>'BBG_VALUE')     IS DISTINCT FROM prev.hist_bbg )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int INTO v_drift_affected FROM drift_upd;

    -- Pass 2: Suppress rows whose SUPPRESS_DATE has passed. Independent
    -- of hist so rows with no prior hist still get expired.
    -- OPEN_DATE is intentionally NOT ratcheted here — a suppression
    -- lapsing is not the same signal as a fresh discovery, so the
    -- original open date is preserved to keep the aging metric honest.
    IF v_suppress_id IS NOT NULL THEN
        WITH bloomberg_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Bloomberg Compare Differences'
        ),
        suppress_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   "SUPPRESS_DATE" = NULL,
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE e."STATUS_ID"    = v_suppress_id
               AND e."SUPPRESS_DATE" IS NOT NULL
               AND e."SUPPRESS_DATE" < v_today
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM bloomberg_rules)
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_suppress_affected FROM suppress_upd;
    END IF;

    RETURN v_drift_affected + v_suppress_affected;
END;
$$;
