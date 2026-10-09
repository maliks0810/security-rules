DROP FUNCTION IF EXISTS public."SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES"();

-- Bloomberg-catalog-scoped revert workflow. For every EXCEPTION row in
-- the 'Bloomberg Compare Differences' catalog that is not currently
-- 'New', flip it back to New when EITHER of
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
    v_override_id       integer;
    v_drift_affected    integer   := 0;
    v_suppress_affected integer   := 0;
    v_override_affected integer   := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID"
      INTO v_suppress_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Suppress'
     LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID"
      INTO v_override_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Override'
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
               -- OPEN_DATE is write-once and is NOT ratcheted by a
               -- drift revert, matching pass 2 below. A value moving is
               -- a change to an exception that was already surfaced,
               -- not a fresh discovery, so the original open date is
               -- preserved to keep the aging metric honest.
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
               "SUPPRESS_DATE" = NULL,
               -- Reverting to New un-closes the row, so its CLOSE_DATE
               -- has to go. CLOSE_DATE is populated iff the status is
               -- Accept or Override and this pass can revert either;
               -- leaving it would hand the grid a 'New' row carrying a
               -- close date.
               "CLOSE_DATE"    = NULL,
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
                   -- Cleared defensively so this pass cannot leave the
                   -- "closed iff Accept / Override" invariant broken.
                   "CLOSE_DATE"    = NULL,
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

    -- Pass 3: Override rows whose ALADDIN_VALUE still differs from their
    -- BBG_VALUE. An Override says "this mismatch is accepted"; while the
    -- two values still disagree the exception is still true, so it is
    -- reopened. Independent of hist - the comparison is between the two
    -- values on the row itself.
    --
    -- Distinct from pass 1: that asks "did either value move since the
    -- last run", this asks "do the two values disagree right now". A row
    -- can be stable across runs and still be a genuine mismatch, which
    -- is the case an Override was hiding.
    --
    -- IS DISTINCT FROM is NULL-safe: two NULLs are not distinct and do
    -- not revert; NULL against a value is distinct and does.
    IF v_override_id IS NOT NULL THEN
        WITH bloomberg_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Bloomberg Compare Differences'
        ),
        override_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   -- Override always carries a CLOSE_DATE, so clearing
                   -- it is required here, not defensive.
                   "CLOSE_DATE"    = NULL,
                   "SUPPRESS_DATE" = NULL,
                   -- OPEN_DATE write-once, as in passes 1 and 2.
                   "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE e."STATUS_ID" = v_override_id
               AND (e."RESULT_DATA"->>'ALADDIN_VALUE')
                   IS DISTINCT FROM (e."RESULT_DATA"->>'BBG_VALUE')
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM bloomberg_rules)
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_override_affected FROM override_upd;
    END IF;

    RETURN v_drift_affected + v_suppress_affected + v_override_affected;
END;
$$;
