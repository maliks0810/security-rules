-- Removes today's freshly produced EXCEPTION rows in scope that are still
-- closed - STATUS 'Accept' or 'Override' - more than one business day
-- after their CLOSE_DATE, so a closed exception stops being written once
-- the day after it was closed has passed.
--
-- Called by ExecuteRules AFTER insert -> inherit -> revert-to-new:
--   * inherit is what carries Accept / Override and CLOSE_DATE forward
--     from EXCEPTION_HIST, so the rows to drop only exist after it;
--   * the catalog's REVERT_TO_NEW_CRITERIA (e.g.
--     SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES) must get its say
--     first. A row it flips back to New is no longer closed, so it is
--     kept and shows up again.
-- A dropped row is never archived, so the last EXCEPTION_HIST row for
-- that (RULE_ID, ASSET_ID) stays the closed one. That keeps the next run
-- inheriting the closure - and keeps the revert SP comparing its values
-- against the ones that were closed - until the values drift.
--
-- "More than one business day": dropped once today is past the first
-- business day after CLOSE_DATE. Weekends only, no holiday calendar
-- (same convention as the Hold date in SP_UPDATE_BULK_STATUS). Offsets
-- by ISO weekday of CLOSE_DATE: Mon-Thu +1, Fri +3, Sat +2, Sun +1. A
-- Monday close still shows Tuesday and drops Wednesday; a Friday close
-- still shows Monday and drops Tuesday.
--
-- Rows with no CLOSE_DATE are kept: there is nothing to measure from.
-- Only today's rows are touched, so an unswept older day is never
-- deleted without being archived.
--
-- Scope semantics match SP_ARCHIVE_EXCEPTIONS / SP_INHERIT_EXCEPTION_STATUSES.
-- Returns the number of rows dropped.

CREATE OR REPLACE PROCEDURE SP_DROP_CLOSED_EXCEPTIONS(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    today    DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected NUMBER := 0;
BEGIN
    DELETE FROM "EXCEPTION"
     WHERE "EXCEPTION_DATE" = :today
       AND "CLOSE_DATE" IS NOT NULL
       AND "STATUS_ID" IN (
           SELECT "EXCEPTION_STATUS_ID"
             FROM "EXCEPTION_STATUS"
            WHERE "NAME" IN ('Accept', 'Override')
       )
       AND :today > DATEADD(
               DAY,
               CASE DAYOFWEEKISO("CLOSE_DATE")
                   WHEN 5 THEN 3
                   WHEN 6 THEN 2
                   ELSE 1
               END,
               "CLOSE_DATE"
           )
       AND "RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM "RULE" r
             JOIN "RULE_CATALOG" rc    ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             LEFT JOIN "RULE_GROUP" rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
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
