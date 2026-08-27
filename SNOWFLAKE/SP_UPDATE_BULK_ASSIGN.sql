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
--   TRUE            - UPDATE RULE.ASSIGN_TO_ID for every named rule.
--                     Exceptions created later inherit it because
--                     InsertExceptions stamps the rule default onto
--                     each new row as it is written.
-- An empty P_RULE_NAMES skips the rule-level write entirely and still
-- reassigns the selected exceptions.
--
-- RULE_ASSIGN_OVERRIDE is not written or read by anything any more:
-- the assignee resolves as COALESCE(EXCEPTION.ASSIGN_TO_ID,
-- RULE.ASSIGN_TO_ID) across every read procedure.
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
    -- With it ticked the UI forces every row selected and locks the
    -- checkboxes, so the EXCEPTION update below covers the whole grid
    -- and this rule write is what makes it stick for rows created
    -- LATER: InsertExceptions stamps RULE.ASSIGN_TO_ID onto each new
    -- exception as it is written.
    --
    -- RULE_ASSIGN_OVERRIDE is no longer involved on either branch. It
    -- is not read by any procedure any more - the assignee resolves as
    -- COALESCE(EXCEPTION.ASSIGN_TO_ID, RULE.ASSIGN_TO_ID) - so there is
    -- nothing to write and nothing to purge.
    IF (:P_RULE_NAMES IS NOT NULL AND :P_RULE_NAMES <> ''
        AND COALESCE(:P_IS_PERMANENT, FALSE)) THEN
        -- RULE has no MODIFIED_DATE / MODIFIED_BY columns (see RULE.sql),
        -- so only the assignee is set here.
        UPDATE "RULE"
           SET "ASSIGN_TO_ID" = :user_id
         WHERE "RULE_NAME" IN (
            SELECT TRIM(t.VALUE::STRING)
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
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
