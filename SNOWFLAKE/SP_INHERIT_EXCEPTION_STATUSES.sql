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
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = h."STATUS_ID",
           -- OPEN_DATE moves to today only when this inherit flips the
           -- row TO 'New' (STATUS_ID = 1). Inheriting Accept / Override
           -- / Suppress leaves the last-New date alone.
           "OPEN_DATE"     = CASE
                                 WHEN h."STATUS_ID" = 1
                                     THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
                                 ELSE e."OPEN_DATE"
                             END,
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
          SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS"
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS",
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
                AND NOT EQUAL_NULL(e."COMMENTS", h."COMMENTS")))
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
