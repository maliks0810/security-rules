DROP FUNCTION IF EXISTS public."SP_INHERIT_EXCEPTION_STATUSES"(text, text);

-- For each EXCEPTION row in scope, carry the last-known STATUS_ID from
-- EXCEPTION_HIST forward. The "last-known" row per (RULE_ID, ASSET_ID)
-- is the one with the most recent (EXCEPTION_DATE DESC, BATCH_ID DESC):
--   * If today has any archived batches, today's max BATCH_ID wins —
--     which represents the state captured on this run's archive call.
--   * If today has no archived rows (first run of a fresh day, or the
--     first archive of the day where nothing existed in EXCEPTION), the
--     ordering falls through to the most recent PREVIOUS date's max
--     BATCH_ID — i.e., last known state from the previous run day.
-- Also bumps MODIFIED_DATE / MODIFIED_BY on any row we actually change,
-- and skips no-op rewrites via IS DISTINCT FROM.
--
-- Scope semantics match SP_GET_RULES (post-CATALOG/RULE split):
--   p_rule_type = 'CATALOG'          → p_rule_name = RULE_CATALOG.NAME
--   p_rule_type = 'GROUP'            → p_rule_name = RULE_GROUP.NAME
--   p_rule_type = 'RULE'             → p_rule_name = RULE.RULE_NAME
--   p_rule_name NULL / empty / 'All' → every catalog.
--
-- Cross-day carry-forward: because last_hist is unfiltered (no date
-- floor / ceiling), the first run of a new day picks up whatever the
-- most recent HIST row is per (RULE_ID, ASSET_ID) — that's yesterday's
-- final state once the SP_ARCHIVE_STALE_DATES cron has swept
-- yesterday's EXCEPTION rows into HIST. So Accept on day N → Accept
-- on day N+1's fresh insert.
--
-- Returns the number of rows whose STATUS_ID actually changed.

CREATE OR REPLACE FUNCTION public."SP_INHERIT_EXCEPTION_STATUSES"(
    p_rule_name text DEFAULT NULL,
    p_rule_type text DEFAULT NULL
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH last_hist AS (
        SELECT DISTINCT ON ("RULE_ID", "ASSET_ID")
               "RULE_ID", "ASSET_ID", "STATUS_ID"
          FROM public."EXCEPTION_HIST"
         WHERE "STATUS_ID" IS NOT NULL
         ORDER BY "RULE_ID", "ASSET_ID",
                  "EXCEPTION_DATE" DESC,
                  "BATCH_ID"       DESC NULLS LAST
    ),
    scoped AS (
        SELECT e."EXCEPTION_ID"
          FROM public."EXCEPTION" e
          JOIN public."RULE"          r  ON r."RULE_ID"           = e."RULE_ID"
          JOIN public."RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID"  = r."RULE_CATALOG_ID"
          LEFT JOIN public."RULE_GROUP" rg ON rg."RULE_GROUP_ID"  = rc."RULE_GROUP_ID"
         WHERE p_rule_name IS NULL
            OR p_rule_name = ''
            OR p_rule_name = 'All'
            OR (UPPER(COALESCE(p_rule_type, 'CATALOG')) = 'CATALOG'
                  AND rc."NAME" = p_rule_name)
            OR (UPPER(p_rule_type) = 'GROUP'
                  AND rg."NAME"  = p_rule_name)
            OR (UPPER(p_rule_type) = 'RULE'
                  AND r."RULE_NAME" = p_rule_name)
    ),
    updated AS (
        UPDATE public."EXCEPTION" e
           SET "STATUS_ID"     = h."STATUS_ID",
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
          FROM last_hist h
         WHERE e."RULE_ID"      = h."RULE_ID"
           AND e."ASSET_ID"     = h."ASSET_ID"
           AND e."EXCEPTION_ID" IN (SELECT "EXCEPTION_ID" FROM scoped)
           AND e."STATUS_ID" IS DISTINCT FROM h."STATUS_ID"
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
