DROP FUNCTION IF EXISTS public."SP_CLEAR_USER_PREFERENCES"(text, text, text);

-- Deletes the saved USER_PREFERENCES row for the (user, rule group,
-- rule catalog) scope, so the grid falls back to its canonical
-- default column order. Powers Settings → Reset Column Headers.
-- Postgres mirror of SNOWFLAKE/SP_CLEAR_USER_PREFERENCES.sql.
--
-- Pass p_rule_catalog as NULL / '' when the LHS tree sits at the
-- group root; the row whose RULE_CATALOG_ID IS NULL is the one
-- removed. IS NOT DISTINCT FROM is the Postgres equivalent of
-- Snowflake's EQUAL_NULL so a NULL catalog matches a NULL column.
--
-- Scoped deliberately narrowly — it clears ONLY the row for the
-- scope the operator is looking at, never the user's other saved
-- layouts.
--
-- Return value:
--   0 — nothing deleted (unknown user, unknown group, unknown
--       catalog name, or no saved layout for the scope). Callers
--       treat 0 as success: "no saved layout" is the state Reset
--       is trying to reach.
--   1 — the saved layout row was deleted.
CREATE OR REPLACE FUNCTION public."SP_CLEAR_USER_PREFERENCES"(
    p_user          text,
    p_rule_group    text,
    p_rule_catalog  text
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id         integer;
    v_rule_group_id   integer;
    v_rule_catalog_id integer;
    v_affected        integer := 0;
BEGIN
    IF p_user IS NULL OR p_user = '' THEN
        RETURN 0;
    END IF;
    IF p_rule_group IS NULL OR p_rule_group = '' THEN
        RETURN 0;
    END IF;

    SELECT "ID" INTO v_user_id
    FROM public."DM_USER"
    WHERE "USER" = p_user
    LIMIT 1;
    IF v_user_id IS NULL THEN
        RETURN 0;
    END IF;

    SELECT "RULE_GROUP_ID" INTO v_rule_group_id
    FROM public."RULE_GROUP"
    WHERE "NAME" = p_rule_group
    LIMIT 1;
    IF v_rule_group_id IS NULL THEN
        RETURN 0;
    END IF;

    IF p_rule_catalog IS NULL OR p_rule_catalog = '' THEN
        v_rule_catalog_id := NULL;
    ELSE
        SELECT "RULE_CATALOG_ID" INTO v_rule_catalog_id
        FROM public."RULE_CATALOG"
        WHERE "NAME" = p_rule_catalog
          AND "RULE_GROUP_ID" = v_rule_group_id
        LIMIT 1;
        IF v_rule_catalog_id IS NULL THEN
            RETURN 0;
        END IF;
    END IF;

    DELETE FROM public."USER_PREFERENCES"
     WHERE "DM_USER_ID"      = v_user_id
       AND "RULE_GROUP_ID"   = v_rule_group_id
       AND "RULE_CATALOG_ID" IS NOT DISTINCT FROM v_rule_catalog_id;

    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
