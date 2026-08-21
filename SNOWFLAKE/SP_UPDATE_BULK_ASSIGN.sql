-- Bulk-assigns a user to an explicit set of EXCEPTION rows.
--
-- P_EXCEPTION_IDS is a comma-separated EXCEPTION_ID list - the rows the
-- operator ticked in the Exceptions grid's bulk-selection column, and
-- the only rows whose ASSIGN_TO_ID is touched. Empty / NULL -> RETURN 0.
--
-- P_RULE_NAMES is NOT a target set. It is the distinct set of rules
-- those selected rows belong to, and drives only the rule-level write:
--   FALSE (default) - INSERT one RULE_ASSIGN_OVERRIDE row per rule
--                     (soft override; RULE.ASSIGN_TO_ID untouched).
--                     Later runs pick up the override via the rao join
--                     in SP_GET_EXCEPTIONS / _HIST / _ASSETS.
--   TRUE            - UPDATE RULE.ASSIGN_TO_ID directly for every
--                     named rule (permanent change to the rule
--                     default). No RULE_ASSIGN_OVERRIDE row is written.
-- An empty P_RULE_NAMES skips the rule-level write entirely and still
-- reassigns the selected exceptions.
--
-- EXCEPTION.ASSIGN_TO_ID is updated regardless of P_IS_PERMANENT so the
-- grid immediately reflects the new assignee. Returns the number of
-- EXCEPTION rows updated.

CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_ASSIGN(
    P_EXCEPTION_IDS VARCHAR,
    P_RULE_NAMES  VARCHAR,
    P_ASSIGN_TO   VARCHAR,
    P_IS_PERMANENT BOOLEAN DEFAULT FALSE
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    user_id  NUMBER := NULL;
    today    DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
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
    ELSEIF (:P_RULE_NAMES IS NOT NULL AND :P_RULE_NAMES <> ''
            AND NOT COALESCE(:P_IS_PERMANENT, FALSE)) THEN
        INSERT INTO "RULE_ASSIGN_OVERRIDE" (
            "RULE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_UNTIL_DATE",
            "CREATED_BY", "CREATED_DATE"
        )
        SELECT r."RULE_ID",
               :user_id,
               :today,
               'system',
               :now_ts
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name;
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
