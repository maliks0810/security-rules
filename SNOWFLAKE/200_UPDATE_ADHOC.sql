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
