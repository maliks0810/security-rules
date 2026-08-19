-- CLEAR_USER_PREFERENCES ------------------------------------------------------
-- Deletes the saved USER_PREFERENCES row for the (user, rule group,
-- rule catalog) scope, so the grid falls back to its canonical
-- default column order. Powers Settings → Reset Column Headers.
-- Name-based inputs and the same NULL-catalog semantics as
-- SP_UPDATE_USER_PREFERENCES / SP_GET_USER_PREFERENCES: pass
-- P_RULE_CATALOG as NULL / '' when the LHS tree sits at the group
-- root, and the row whose RULE_CATALOG_ID IS NULL is the one removed.
--
-- Scoped deliberately narrowly — it clears ONLY the row for the
-- scope the operator is looking at, never the user's other saved
-- layouts, so resetting one group's headers can't wipe another's.
--
-- Return value:
--   0 — nothing deleted (unknown user, unknown group, unknown
--       catalog name, or simply no saved layout for the scope).
--       The client treats 0 as success: "no saved layout" is the
--       state Reset is trying to reach.
--   1 — the saved layout row was deleted.
CREATE OR REPLACE PROCEDURE SP_CLEAR_USER_PREFERENCES(
    P_USER          VARCHAR,
    P_RULE_GROUP    VARCHAR,
    P_RULE_CATALOG  VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    user_id         NUMBER := NULL;
    rule_group_id   NUMBER := NULL;
    rule_catalog_id NUMBER := NULL;
    affected        NUMBER := 0;
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

    DELETE FROM "USER_PREFERENCES"
     WHERE "DM_USER_ID"    = :user_id
       AND "RULE_GROUP_ID" = :rule_group_id
       AND EQUAL_NULL("RULE_CATALOG_ID", :rule_catalog_id);

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
