DROP FUNCTION IF EXISTS public."SP_UPDATE_USER_PREFERENCES"(text, text, text, text);

-- Upserts the operator's UI preferences (today: COLUMN_ORDER) into
-- USER_PREFERENCES for the (user, rule group, rule catalog) tuple.
-- Inputs are name-based so the client never has to know surrogate
-- IDs. Pass p_rule_catalog as NULL (or '') when the LHS tree is at
-- the group root — the row is then scoped to the whole group and
-- RULE_CATALOG_ID is stored NULL.
--
-- Return value:
--   0 — no-op (unknown user, unknown group, or unknown catalog
--       name when one was supplied).
--   1 — inserted a new preferences row.
--   2 — updated an existing preferences row.
--
-- (DM_USER_ID, RULE_GROUP_ID, RULE_CATALOG_ID) uniqueness is
-- enforced here rather than by DDL, matching the Snowflake shape.
-- IS NOT DISTINCT FROM is the Postgres equivalent of Snowflake's
-- EQUAL_NULL so a NULL RULE_CATALOG_ID matches another NULL.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_USER_PREFERENCES"(
    p_user          text,
    p_rule_group    text,
    p_rule_catalog  text,
    p_column_order  text
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id         integer;
    v_rule_group_id   integer;
    v_rule_catalog_id integer;
    v_existing_cnt    integer;
    v_now_ts          timestamp := (NOW() AT TIME ZONE 'UTC');
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

    SELECT COUNT(*) INTO v_existing_cnt
    FROM public."USER_PREFERENCES"
    WHERE "DM_USER_ID"    = v_user_id
      AND "RULE_GROUP_ID" = v_rule_group_id
      AND "RULE_CATALOG_ID" IS NOT DISTINCT FROM v_rule_catalog_id;

    IF v_existing_cnt > 0 THEN
        UPDATE public."USER_PREFERENCES"
           SET "COLUMN_ORDER"    = p_column_order,
               "MODIFIED_DATE"   = v_now_ts,
               "MODIFIED_BY"     = 'system'
         WHERE "DM_USER_ID"      = v_user_id
           AND "RULE_GROUP_ID"   = v_rule_group_id
           AND "RULE_CATALOG_ID" IS NOT DISTINCT FROM v_rule_catalog_id;
        RETURN 2;
    ELSE
        INSERT INTO public."USER_PREFERENCES" (
            "DM_USER_ID", "RULE_GROUP_ID", "RULE_CATALOG_ID",
            "COLUMN_ORDER", "CREATED_DATE", "CREATED_BY"
        ) VALUES (
            v_user_id, v_rule_group_id, v_rule_catalog_id,
            p_column_order, v_now_ts, 'system'
        );
        RETURN 1;
    END IF;
END;
$$;
