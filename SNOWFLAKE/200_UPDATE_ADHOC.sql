-- 200_UPDATE_ADHOC.sql
--
-- One-off statements that have to run against an EXISTING deployment
-- and have no home in a per-object file, because the object file
-- describes the CURRENT shape of its procedure and nothing else.
--
-- Right now that means dropping superseded procedure overloads.
-- Snowflake identifies a procedure by name AND argument signature, so
-- CREATE OR REPLACE only replaces the definition with the identical
-- signature. When a procedure gains or loses a parameter, the old
-- definition stays resident alongside the new one, and any caller
-- passing the old argument count silently keeps resolving to the old
-- behaviour. Dropping by explicit signature is the only way to retire
-- it.
--
-- RUN ORDER: after the per-object procedure files, not before. Each
-- DROP below names a signature that no longer exists in source, so the
-- new definition must already be in place - otherwise a deploy leaves
-- the schema with no procedure of that name at all between the two
-- steps.
--
-- Every statement is IF EXISTS and therefore idempotent: safe to re-run,
-- and a no-op on a fresh schema that never had the old signatures.
--
-- Postgres mirrors keep their DROPs inline in postgres/*.sql. That is
-- not an inconsistency to fix: CREATE OR REPLACE FUNCTION in Postgres
-- also refuses to change a signature, so the drop has to be part of the
-- same script that recreates the function for it to apply at all.

-- SP_UPDATE_BULK_ASSIGN: 3 args -> 4.
-- Targeting moved from rule names to explicit EXCEPTION_IDs, adding
-- P_EXCEPTION_IDS as the new first parameter. The old definition
-- assigns by whole rule, which is exactly the bug that change fixed.
DROP PROCEDURE IF EXISTS SP_UPDATE_BULK_ASSIGN(VARCHAR, VARCHAR, BOOLEAN);

-- SP_GET_EXCEPTION_COUNTS_BY_GROUP: 6 args -> 7.
-- P_USE_HIST was added so the Number of Exceptions panel counts
-- EXCEPTION_HIST for archived dates instead of the live EXCEPTION
-- table. The old definition always counts EXCEPTION and so reports 0
-- for every rule group on any historical date.
DROP PROCEDURE IF EXISTS SP_GET_EXCEPTION_COUNTS_BY_GROUP(
    VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, DATE
);

-- SP_GET_EXCEPTIONS: 11 args -> 12.
-- P_SECURITY_GROUP was added, selecting a separate query that joins
-- DIM_SECURITY. The old definition cannot filter by security group.
--
-- Note the Snowflake read path normally calls UDF_GET_EXCEPTIONS; this
-- procedure is invoked only for the security-group case (and kept as a
-- documented rollback), so a stale overload here is quieter than the
-- other two - but no less wrong.
DROP PROCEDURE IF EXISTS SP_GET_EXCEPTIONS(
    VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR, VARCHAR,
    VARCHAR, VARCHAR, VARCHAR, VARCHAR, DATE
);

-- Backfill: EXCEPTION.ASSIGN_TO_ID is never NULL.
--
-- "Unassigned" is a real DM_USER row rather than an absent value, so
-- every exception points at a user and read paths never reason about
-- NULL. Every write path now upholds that - the two assign procedures
-- resolve an empty name to 'Unassigned', and InsertExceptions stamps it
-- on rows whose rule has no default - but rows written BEFORE those
-- changes still carry NULL and need bringing into line once.
--
-- Guarded on the row existing, so on a schema without it this updates
-- nothing rather than writing NULL over NULL. Idempotent: re-running
-- matches no rows, because the first run left none.
UPDATE "EXCEPTION"
   SET "ASSIGN_TO_ID"  = (
           SELECT "ID" FROM "DM_USER" WHERE "USER" = 'Unassigned' LIMIT 1
       ),
       "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
       "MODIFIED_BY"   = 'system'
 WHERE "ASSIGN_TO_ID" IS NULL
   AND EXISTS (SELECT 1 FROM "DM_USER" WHERE "USER" = 'Unassigned');

-- EXCEPTION_HIST carries the same column and the same reasoning, so the
-- archive is brought into line too. Without this a historical-date view
-- shows blank assignees where the live grid shows Unassigned.
UPDATE "EXCEPTION_HIST"
   SET "ASSIGN_TO_ID" = (
           SELECT "ID" FROM "DM_USER" WHERE "USER" = 'Unassigned' LIMIT 1
       )
 WHERE "ASSIGN_TO_ID" IS NULL
   AND EXISTS (SELECT 1 FROM "DM_USER" WHERE "USER" = 'Unassigned');

-- Backfill: CLOSE_DATE is populated iff the status is closed.
--
-- 'Accept' and 'Override' are the closed statuses and carry a date;
-- every other status clears it. Rows that took a transition before that
-- rule settled are out of step in BOTH directions, so there are two
-- statements.
--
-- SP_UPDATE_CLOSE_DATE converges these on its own, so this only matters
-- where that job is not scheduled — but both are idempotent and match
-- nothing on a second run.

-- Open statuses must not carry a date. Covers rows stamped while
-- 'Research' was still treated as a close, and rows held before 'Hold'
-- joined the pending list.
UPDATE "EXCEPTION"
   SET "CLOSE_DATE"    = NULL,
       "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
       "MODIFIED_BY"   = 'system'
 WHERE "CLOSE_DATE" IS NOT NULL
   AND "STATUS_ID" IN (
       SELECT "EXCEPTION_STATUS_ID"
         FROM "EXCEPTION_STATUS"
        WHERE "NAME" NOT IN ('Accept', 'Override')
   );

-- Closed statuses must carry one. 'Override' only began stamping
-- CLOSE_DATE with this change, so rows already sitting in Override have
-- none. Stamped with today rather than a guessed historical date: the
-- day the row was actually overridden is not recoverable from the live
-- table, and today is at least honest about when the value was set.
UPDATE "EXCEPTION"
   SET "CLOSE_DATE"    = TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())),
       "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
       "MODIFIED_BY"   = 'system'
 WHERE "CLOSE_DATE" IS NULL
   AND "STATUS_ID" IN (
       SELECT "EXCEPTION_STATUS_ID"
         FROM "EXCEPTION_STATUS"
        WHERE "NAME" IN ('Accept', 'Override')
   );

-- The archive is left ALONE on purpose. EXCEPTION_HIST is a record of
-- what each row looked like on the day it was archived, and on those
-- days a researched row genuinely did carry a close date. Rewriting it
-- would falsify history rather than correct it - unlike the assignee
-- backfill above, which fills a gap rather than restating a past fact.

-- Backfill: restore OPEN_DATE to the day the exception was first seen.
--
-- OPEN_DATE is now write-once - it means "the day this exception was
-- first surfaced" and no write path overwrites it. Before that,
-- SP_INHERIT_EXCEPTION_STATUSES re-stamped today every time it inherited
-- 'New', and InsertExceptions stamps today on each freshly inserted New
-- row, so every batch moved the date forward and the whole table showed
-- the latest run date. The aging that column exists to express was lost
-- daily.
--
-- The original date IS recoverable. EXCEPTION_HIST keeps one archived
-- row per run, so the earliest EXCEPTION_DATE for a (RULE_ID, ASSET_ID)
-- is the day that exception first appeared - independent of the
-- OPEN_DATE the old logic wrote, which is why EXCEPTION_DATE is used as
-- the source rather than MIN("OPEN_DATE").
--
-- Only moves dates BACKWARDS, and only for rows that already carry one.
-- A NULL OPEN_DATE means the row has never been New, and the rule is to
-- stamp only on New - so those are left alone rather than invented.
--
-- Idempotent: after one run OPEN_DATE equals the minimum, so the
-- strict > predicate matches nothing on a re-run.
UPDATE "EXCEPTION" e
   SET "OPEN_DATE"     = f.first_seen,
       "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
       "MODIFIED_BY"   = 'system'
  FROM (
      SELECT "RULE_ID",
             "ASSET_ID",
             MIN("EXCEPTION_DATE") AS first_seen
        FROM "EXCEPTION_HIST"
       WHERE "EXCEPTION_DATE" IS NOT NULL
       GROUP BY "RULE_ID", "ASSET_ID"
  ) f
 WHERE e."RULE_ID"   = f."RULE_ID"
   AND e."ASSET_ID"  = f."ASSET_ID"
   AND e."OPEN_DATE" IS NOT NULL
   AND e."OPEN_DATE" > TO_DATE(f.first_seen);

-- EXCEPTION_HIST is left alone here for the same reason as the
-- CLOSE_DATE backfill above: each archived row is a record of what the
-- live row looked like on the day it was archived. Going forward the
-- correct date is carried into the archive by the normal archive ->
-- insert -> inherit cycle, so hist self-corrects from the next run on.
