-- Bulk-assigns a user to every EXCEPTION belonging to any of the passed
-- rule names. Persistence target depends on P_IS_PERMANENT:
--   FALSE (default) — INSERT one RULE_ASSIGN_OVERRIDE row per rule
--                     (soft override; RULE.ASSIGN_TO_ID untouched).
--                     Later runs pick up the override via the rao join
--                     in SP_GET_EXCEPTIONS / _HIST / _ASSETS.
--   TRUE            — UPDATE RULE.ASSIGN_TO_ID directly for every
--                     matched rule (permanent change to the rule
--                     default). No RULE_ASSIGN_OVERRIDE row is written.
--
-- EXCEPTION.ASSIGN_TO_ID is updated for every existing row regardless
-- of P_IS_PERMANENT so the current grid immediately reflects the new
-- assignee. Returns the number of EXCEPTION rows updated.

CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_ASSIGN(
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

    IF (:P_RULE_NAMES IS NULL OR :P_RULE_NAMES = '') THEN
        RETURN 0;
    END IF;

    IF (:P_IS_PERMANENT) THEN
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
    ELSE
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
     WHERE "RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM LATERAL SPLIT_TO_TABLE(:P_RULE_NAMES, ',') t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name
     );

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
