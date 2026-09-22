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
               "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS", "CLOSE_DATE",
               "ASSIGN_TO_ID", "OPEN_DATE"
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
               -- OPEN_DATE is INHERITED, never re-stamped. It records
               -- when an exception was first surfaced, so it has to
               -- survive the archive -> insert -> inherit cycle that
               -- runs on every batch.
               --
               -- This used to set today whenever it inherited 'New',
               -- which is why every row showed the latest run date:
               -- InsertExceptions already stamps today on each freshly
               -- inserted New row, and this then confirmed it rather
               -- than restoring the original. COALESCE prefers the
               -- archived value and falls back to whatever the insert
               -- stamped, so a genuinely first-seen row still gets
               -- today.
               "OPEN_DATE"     = COALESCE(h."OPEN_DATE", e."OPEN_DATE"),
               -- CLOSE_DATE carries over from the last EXCEPTION_HIST
               -- row for the same (RULE_ID, ASSET_ID) so the day the
               -- row was originally closed survives the archive →
               -- insert → inherit cycle. NULL on the hist side leaves
               -- the live row's date alone (via COALESCE). Pass 2 of
               -- SP_UPDATE_CLOSE_DATE backstops the case where hist
               -- has no CLOSE_DATE yet but the current status is
               -- Accept / Research.
               "CLOSE_DATE"    = COALESCE(h."CLOSE_DATE", e."CLOSE_DATE"),
               -- COMMENTS carry over from the last EXCEPTION_HIST row
               -- for the same (RULE_ID, ASSET_ID). Anything the
               -- operator typed while the row sat in Accept / Suppress
               -- / Override / … is preserved across rule re-runs.
               -- NULL / unset on the hist side leaves the live row's
               -- comment alone via COALESCE.
               "COMMENTS"      = COALESCE(h."COMMENTS", e."COMMENTS"),
               -- ASSIGN_TO_ID carries forward from the last archived run
               -- whenever that run had a REAL owner, so an exception
               -- stays with whoever was working it across the intraday
               -- batch and the overnight roll.
               --
               -- NULL or Unassigned on the hist side means nobody owned
               -- it, and the live row keeps what InsertExceptions
               -- stamped from RULE.ASSIGN_TO_ID (falling back to
               -- Unassigned). So the rule default applies exactly when
               -- the previous run had no owner, and never overrides a
               -- human assignment.
               --
               -- COALESCE to -1 so a schema missing the Unassigned row
               -- degrades to "nothing equals it" - real assignees still
               -- carry forward rather than the inheritance silently
               -- switching off.
               "ASSIGN_TO_ID"  = CASE
                                     WHEN h."ASSIGN_TO_ID" IS NOT NULL
                                          AND h."ASSIGN_TO_ID" <> COALESCE(
                                              (SELECT "ID" FROM public."DM_USER"
                                                WHERE "USER" = 'Unassigned' LIMIT 1), -1)
                                         THEN h."ASSIGN_TO_ID"
                                     ELSE e."ASSIGN_TO_ID"
                                 END,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
          FROM last_hist h
         WHERE e."RULE_ID"      = h."RULE_ID"
           AND e."ASSET_ID"     = h."ASSET_ID"
           AND e."EXCEPTION_ID" IN (SELECT "EXCEPTION_ID" FROM scoped)
           AND (e."STATUS_ID" IS DISTINCT FROM h."STATUS_ID"
                OR (h."COMMENTS" IS NOT NULL
                    AND e."COMMENTS" IS DISTINCT FROM h."COMMENTS")
                OR (h."CLOSE_DATE" IS NOT NULL
                    AND e."CLOSE_DATE" IS DISTINCT FROM h."CLOSE_DATE")
                OR (h."ASSIGN_TO_ID" IS NOT NULL
                    AND h."ASSIGN_TO_ID" <> COALESCE(
                        (SELECT "ID" FROM public."DM_USER"
                          WHERE "USER" = 'Unassigned' LIMIT 1), -1)
                    AND e."ASSIGN_TO_ID" IS DISTINCT FROM h."ASSIGN_TO_ID")
                OR (h."OPEN_DATE" IS NOT NULL
                    AND e."OPEN_DATE" IS DISTINCT FROM h."OPEN_DATE"))
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
