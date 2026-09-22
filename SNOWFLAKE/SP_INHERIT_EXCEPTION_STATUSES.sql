-- For each EXCEPTION row in scope, carry the last-known STATUS_ID from
-- EXCEPTION_HIST forward, keyed by (RULE_ID, ASSET_ID). The "last" row
-- is picked by (EXCEPTION_DATE DESC, BATCH_ID DESC), which naturally
-- gives today's max batch when today has archives, else falls back to
-- the most recent prior date's max batch. Skips no-op rewrites.
--
-- Scope semantics match SP_ARCHIVE_EXCEPTIONS / SP_GET_RULES.

CREATE OR REPLACE PROCEDURE SP_INHERIT_EXCEPTION_STATUSES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    affected NUMBER := 0;
    -- "Unassigned" is a real DM_USER row, so an inherited assignee of
    -- Unassigned carries no information and must NOT override whatever
    -- InsertExceptions just stamped from the rule default. COALESCE to
    -- -1 so a schema missing that row degrades to "nothing equals it",
    -- which still carries real assignees forward rather than silently
    -- disabling the inheritance.
    unassigned_id NUMBER := NULL;
BEGIN
    SELECT "ID" INTO :unassigned_id
    FROM "DM_USER"
    WHERE "USER" = 'Unassigned'
    LIMIT 1;

    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = h."STATUS_ID",
           -- ASSIGN_TO_ID carries forward from the last archived run
           -- whenever that run had a REAL owner, so an exception stays
           -- with whoever was working it across the intraday batch and
           -- the overnight roll.
           --
           -- NULL or Unassigned on the hist side means nobody owned it,
           -- and the live row keeps what InsertExceptions stamped from
           -- RULE.ASSIGN_TO_ID (falling back to Unassigned). So the rule
           -- default applies exactly when the previous run had no owner
           -- and never overrides a human assignment.
           "ASSIGN_TO_ID"  = CASE
                                 WHEN h."ASSIGN_TO_ID" IS NOT NULL
                                      AND h."ASSIGN_TO_ID" <> COALESCE(:unassigned_id, -1)
                                     THEN h."ASSIGN_TO_ID"
                                 ELSE e."ASSIGN_TO_ID"
                             END,
           -- OPEN_DATE is INHERITED, never re-stamped. It records when
           -- an exception was first surfaced, so it has to survive the
           -- archive -> insert -> inherit cycle that runs on every
           -- batch.
           --
           -- This used to set today whenever it inherited 'New', which
           -- is why every row showed the latest run date: InsertExceptions
           -- already stamps today on each freshly inserted New row, and
           -- this then confirmed it rather than restoring the original.
           -- COALESCE prefers the archived value and falls back to
           -- whatever the insert stamped, so a genuinely first-seen row
           -- still gets today.
           "OPEN_DATE"     = COALESCE(h."OPEN_DATE", e."OPEN_DATE"),
           -- CLOSE_DATE carries over from the last EXCEPTION_HIST row
           -- for the same (RULE_ID, ASSET_ID) so the day the row was
           -- originally closed survives the archive → insert → inherit
           -- cycle. NULL on the hist side leaves the live row's date
           -- alone (via COALESCE). Pass 2 of SP_UPDATE_CLOSE_DATE
           -- backstops the case where hist has no CLOSE_DATE yet but
           -- the current status is Accept / Research.
           "CLOSE_DATE"    = COALESCE(h."CLOSE_DATE", e."CLOSE_DATE"),
           -- COMMENTS carry over from the last EXCEPTION_HIST row for
           -- the same (RULE_ID, ASSET_ID). Anything the operator typed
           -- while the row sat in Accept / Suppress / Override / … is
           -- preserved across rule re-runs. NULL / empty on the hist
           -- side leaves the live row's comment alone via COALESCE so
           -- a cleared comment on the hist side doesn't blank an
           -- unrelated freshly-typed live comment.
           "COMMENTS"      = COALESCE(h."COMMENTS", e."COMMENTS"),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
      FROM (
          SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS", "CLOSE_DATE", "ASSIGN_TO_ID", "OPEN_DATE"
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS", "CLOSE_DATE", "ASSIGN_TO_ID", "OPEN_DATE",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
                 WHERE "STATUS_ID" IS NOT NULL
            )
           WHERE rn = 1
      ) h
     WHERE e."RULE_ID"  = h."RULE_ID"
       AND e."ASSET_ID" = h."ASSET_ID"
       AND (e."STATUS_ID" IS NULL
            OR e."STATUS_ID" <> h."STATUS_ID"
            OR (h."COMMENTS" IS NOT NULL
                AND NOT EQUAL_NULL(e."COMMENTS", h."COMMENTS"))
            OR (h."CLOSE_DATE" IS NOT NULL
                AND NOT EQUAL_NULL(e."CLOSE_DATE", h."CLOSE_DATE"))
            OR (h."ASSIGN_TO_ID" IS NOT NULL
                AND h."ASSIGN_TO_ID" <> COALESCE(:unassigned_id, -1)
                AND NOT EQUAL_NULL(e."ASSIGN_TO_ID", h."ASSIGN_TO_ID"))
            OR (h."OPEN_DATE" IS NOT NULL
                AND NOT EQUAL_NULL(e."OPEN_DATE", h."OPEN_DATE")))
       AND e."EXCEPTION_ID" IN (
           SELECT e2."EXCEPTION_ID"
             FROM "EXCEPTION" e2
             JOIN "RULE"          r  ON r."RULE_ID"          = e2."RULE_ID"
             JOIN "RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             LEFT JOIN "RULE_GROUP" rg ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
            WHERE :P_RULE_NAME IS NULL
               OR :P_RULE_NAME = ''
               OR :P_RULE_NAME = 'All'
               OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) = 'CATALOG'
                     AND rc."NAME" = :P_RULE_NAME)
               OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                     AND rg."NAME"  = :P_RULE_NAME)
               OR (UPPER(:P_RULE_TYPE) = 'RULE'
                     AND r."RULE_NAME" = :P_RULE_NAME)
       );
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
