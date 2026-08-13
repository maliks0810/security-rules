-- UPDATE_USER_PREFERENCES -----------------------------------------------------
-- Upserts the operator's UI preferences (today: COLUMN_ORDER) into
-- USER_PREFERENCES for the (user, rule group, rule catalog) tuple.
-- Inputs are name-based so the client never has to know surrogate
-- IDs — the proc resolves DM_USER.USER, RULE_GROUP.NAME, and
-- RULE_CATALOG.NAME internally.
--
-- Inputs:
--   P_USER          — DM_USER."USER" display name (Okta-resolved
--                     once integration lands; hard-coded pre-cutover).
--   P_RULE_GROUP    — RULE_GROUP.NAME (e.g. 'Security Master').
--   P_RULE_CATALOG  — RULE_CATALOG.NAME. Pass NULL / '' when the LHS
--                     tree is at the group root (no catalog drilled
--                     into) — the row is then scoped to the whole
--                     group and RULE_CATALOG_ID is stored NULL.
--   P_COLUMN_ORDER  — opaque VARCHAR the client encodes (JSON array
--                     of grid column names today).
--
-- Return value:
--   0 — no-op (unknown user, unknown group, or unknown catalog name
--       when one was supplied). The client should treat 0 as an
--       error and surface a message.
--   1 — inserted a new preferences row.
--   2 — updated an existing preferences row.
--
-- (DM_USER_ID, RULE_GROUP_ID, RULE_CATALOG_ID) uniqueness is
-- enforced here rather than by DDL because Snowflake has no true
-- unique constraint. EQUAL_NULL is used so a NULL RULE_CATALOG_ID
-- matches another NULL (group-root scope).
CREATE OR REPLACE PROCEDURE SP_UPDATE_USER_PREFERENCES(
    P_USER          VARCHAR,
    P_RULE_GROUP    VARCHAR,
    P_RULE_CATALOG  VARCHAR,
    P_COLUMN_ORDER  VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    user_id         NUMBER := NULL;
    rule_group_id   NUMBER := NULL;
    rule_catalog_id NUMBER := NULL;
    existing_cnt    NUMBER := 0;
    now_ts          TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
BEGIN
    IF (:P_USER IS NULL OR :P_USER = '') THEN
        RETURN 0;
    END IF;
    IF (:P_RULE_GROUP IS NULL OR :P_RULE_GROUP = '') THEN
        RETURN 0;
    END IF;

    SELECT "ID" INTO :user_id
    FROM "DM_USER"
    WHERE "USER" = :P_USER
    LIMIT 1;
    IF (:user_id IS NULL) THEN
        RETURN 0;
    END IF;

    SELECT "RULE_GROUP_ID" INTO :rule_group_id
    FROM "RULE_GROUP"
    WHERE "NAME" = :P_RULE_GROUP
    LIMIT 1;
    IF (:rule_group_id IS NULL) THEN
        RETURN 0;
    END IF;

    IF (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = '') THEN
        rule_catalog_id := NULL;
    ELSE
        SELECT "RULE_CATALOG_ID" INTO :rule_catalog_id
        FROM "RULE_CATALOG"
        WHERE "NAME" = :P_RULE_CATALOG
          AND "RULE_GROUP_ID" = :rule_group_id
        LIMIT 1;
        IF (:rule_catalog_id IS NULL) THEN
            RETURN 0;
        END IF;
    END IF;

    SELECT COUNT(*) INTO :existing_cnt
    FROM "USER_PREFERENCES"
    WHERE "DM_USER_ID" = :user_id
      AND "RULE_GROUP_ID" = :rule_group_id
      AND EQUAL_NULL("RULE_CATALOG_ID", :rule_catalog_id);

    IF (:existing_cnt > 0) THEN
        UPDATE "USER_PREFERENCES"
           SET "COLUMN_ORDER"  = :P_COLUMN_ORDER,
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE "DM_USER_ID"    = :user_id
           AND "RULE_GROUP_ID" = :rule_group_id
           AND EQUAL_NULL("RULE_CATALOG_ID", :rule_catalog_id);
        RETURN 2;
    ELSE
        INSERT INTO "USER_PREFERENCES" (
            "DM_USER_ID", "RULE_GROUP_ID", "RULE_CATALOG_ID",
            "COLUMN_ORDER", "CREATED_DATE", "CREATED_BY"
        ) VALUES (
            :user_id, :rule_group_id, :rule_catalog_id,
            :P_COLUMN_ORDER, :now_ts, 'system'
        );
        RETURN 1;
    END IF;
END;
$$;
