-- Bulk-assigns a user to an explicit set of EXCEPTION rows.
--
-- P_EXCEPTION_IDS is a comma-separated EXCEPTION_ID list - the rows the
-- operator ticked in the Exceptions grid's bulk-selection column, and
-- the only rows whose ASSIGN_TO_ID is touched. Empty / NULL -> RETURN 0.
--
-- P_RULE_NAMES is NOT a target set. It is the distinct set of rules
-- those selected rows belong to, and it drives ONLY the permanent
-- rule-level write:
--   FALSE (default) - no rule-level write at all. Only the selected
--                     EXCEPTION rows change.
--   TRUE            - UPDATE RULE.ASSIGN_TO_ID for every named rule so
--                     future exceptions inherit the assignee, and purge
--                     any stale RULE_ASSIGN_OVERRIDE rows for them.
-- An empty P_RULE_NAMES skips the rule-level write entirely and still
-- reassigns the selected exceptions.
--
-- The FALSE branch deliberately writes no RULE_ASSIGN_OVERRIDE row:
-- that override reassigned every unticked exception of the rule that
-- had no assignee of its own (see the note at the branch below).
--
-- EXCEPTION.ASSIGN_TO_ID is updated regardless of P_IS_PERMANENT so the
-- grid immediately reflects the new assignee. Returns the number of
-- EXCEPTION rows updated.

-- This procedure's signature changed arity (3 args -> 4) when targeting
-- moved from rule names to exception ids. Snowflake overloads procedures
-- by signature, so CREATE OR REPLACE below does NOT touch the old 3-arg
-- definition: without this DROP it stays live alongside the new one,
-- still assigning by whole rule. The Postgres mirror drops its old
-- signatures the same way.
DROP PROCEDURE IF EXISTS SP_UPDATE_BULK_ASSIGN(VARCHAR, VARCHAR, BOOLEAN);

CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_ASSIGN(
    P_EXCEPTION_IDS VARCHAR,
    P_RULE_NAMES  VARCHAR,
    P_ASSIGN_TO   VARCHAR,
    P_IS_PERMANENT BOOLEAN DEFAULT FALSE
)
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    user_id  NUMBER := NULL;
    now_ts   TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    affected NUMBER := 0;
BEGIN
    IF (:P_ASSIGN_TO IS NULL OR :P_ASSIGN_TO = '') THEN
        RETURN 0;
    END IF;

    SELECT "ID" INTO :user_id
    FROM "DM_USER"
    WHERE "USER" = :P_ASSIGN_TO
    LIMIT 1;

    IF (:user_id IS NULL) THEN
        RETURN 0;
    END IF;

    -- The selection is what gets reassigned, so an empty id list is the
    -- only fatal case. An empty P_RULE_NAMES just means "no rule-level
    -- side effect" and still reassigns the selected exceptions.
    IF (:P_EXCEPTION_IDS IS NULL OR :P_EXCEPTION_IDS = '') THEN
        RETURN 0;
    END IF;

    -- Rule-level write ONLY when the operator ticked Is Permanent.
    --
    -- There used to be a second branch here: when Is Permanent was off,
    -- one RULE_ASSIGN_OVERRIDE row was inserted per rule. That fitted a
    -- bulk assign that targeted a whole rule, but it is wrong now that
    -- it targets ticked rows. SP_GET_EXCEPTIONS displays
    -- COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID"),
    -- so the override reassigned every UNTICKED exception of the rule
    -- that had no assignee of its own: ticking 2 rows of a 3-row rule
    -- reported "2 assigned" and showed 3, and where no row had an
    -- assignee the entire rule appeared to change.
    IF (:P_RULE_NAMES IS NOT NULL AND :P_RULE_NAMES <> ''
        AND COALESCE(:P_IS_PERMANENT, FALSE)) THEN
        -- RULE has no MODIFIED_DATE / MODIFIED_BY columns (see RULE.sql),
        -- so only the assignee is set here. The permanent write becomes
        -- the new rule default; SP_GET_EXCEPTIONS / _HIST / _ASSETS
        -- pick it up via the r."ASSIGN_TO_ID" leg of the COALESCE
        -- when no per-row or rao override wins.
        UPDATE "RULE"
           SET "ASSIGN_TO_ID" = :user_id
         WHERE "RULE_NAME" IN (
            SELECT TRIM(t.VALUE::STRING)
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
         );

        -- Purge any pre-existing soft overrides for these rules —
        -- once the rule default is set permanently, a stale rao row
        -- pointing at a different user would still win over
        -- RULE.ASSIGN_TO_ID via the COALESCE precedence and silently
        -- override the permanent assignment. Deleting them keeps
        -- the RULE row as the sole source of truth.
        DELETE FROM "RULE_ASSIGN_OVERRIDE"
         WHERE "RULE_ID" IN (
            SELECT r."RULE_ID"
            FROM "RULE" r
            JOIN (
                SELECT TRIM(t.VALUE::STRING) AS rule_name
                FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
                WHERE TRIM(t.VALUE::STRING) <> ''
            ) req
              ON r."RULE_NAME" = req.rule_name
         );
    END IF;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" IN (
        SELECT TRY_TO_NUMBER(TRIM(t.VALUE::STRING))
        FROM TABLE(SPLIT_TO_TABLE(:P_EXCEPTION_IDS, ',')) t
        WHERE TRY_TO_NUMBER(TRIM(t.VALUE::STRING)) IS NOT NULL
     );

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
