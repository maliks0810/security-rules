DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_ASSIGN"(text, text);
DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_ASSIGN"(text, text, boolean);

-- Bulk-assigns a user to every EXCEPTION belonging to any of the passed
-- rule names. Persistence target depends on p_is_permanent:
--   FALSE (default) — INSERT one RULE_ASSIGN_OVERRIDE row per rule
--                     (soft override; RULE.ASSIGN_TO_ID untouched).
--   TRUE            — UPDATE RULE.ASSIGN_TO_ID directly for every
--                     matched rule (permanent). No override row is
--                     written.
-- Regardless of p_is_permanent, EXCEPTION.ASSIGN_TO_ID is updated for
-- every existing row so the current grid immediately reflects the new
-- assignee. Rule names are passed as a plain comma-separated string
-- (matches the SNOWFLAKE contract). Empty p_rule_names / unknown
-- p_assign_to → 0-row no-op. Returns the number of EXCEPTION rows
-- updated.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_BULK_ASSIGN"(
    p_rule_names   text,
    p_assign_to    text,
    p_is_permanent boolean DEFAULT false
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id integer;
    v_today   date := (NOW() AT TIME ZONE 'UTC')::date;
    v_now_ts  timestamp := (NOW() AT TIME ZONE 'UTC');
    v_names   text[];
    v_affected integer := 0;
BEGIN
    IF p_assign_to IS NULL OR p_assign_to = '' THEN
        RETURN 0;
    END IF;

    SELECT "ID" INTO v_user_id
    FROM public."DM_USER"
    WHERE "USER" = p_assign_to
    LIMIT 1;

    IF v_user_id IS NULL THEN
        RETURN 0;
    END IF;

    IF p_rule_names IS NULL OR p_rule_names = '' THEN
        RETURN 0;
    END IF;

    -- Trim + drop empty tokens so trailing / adjacent commas don't
    -- become empty rule-name lookups. Column alias `AS t(name)` is
    -- explicit — bare `unnest(...) AS t` gives column `unnest`, not `t`.
    SELECT ARRAY(
        SELECT btrim(t.name)
        FROM unnest(string_to_array(p_rule_names, ',')) AS t(name)
        WHERE btrim(t.name) <> ''
    ) INTO v_names;

    IF v_names IS NULL OR array_length(v_names, 1) IS NULL THEN
        RETURN 0;
    END IF;

    IF p_is_permanent THEN
        -- RULE has no MODIFIED_DATE / MODIFIED_BY columns (see
        -- RULE_pg.sql), so only the assignee is set here.
        UPDATE public."RULE" r
           SET "ASSIGN_TO_ID" = v_user_id
         WHERE r."RULE_NAME" = ANY(v_names);

        -- Purge any pre-existing soft overrides for these rules —
        -- otherwise a stale rao row would still win over the new
        -- RULE.ASSIGN_TO_ID via the COALESCE precedence in
        -- SP_GET_EXCEPTIONS / _HIST / _ASSETS.
        DELETE FROM public."RULE_ASSIGN_OVERRIDE"
         WHERE "RULE_ID" IN (
            SELECT r."RULE_ID"
            FROM public."RULE" r
            WHERE r."RULE_NAME" = ANY(v_names)
         );
    ELSE
        INSERT INTO public."RULE_ASSIGN_OVERRIDE" (
            "RULE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_UNTIL_DATE",
            "CREATED_BY", "CREATED_DATE"
        )
        SELECT r."RULE_ID",
               v_user_id,
               v_today,
               'system',
               v_now_ts
        FROM public."RULE" r
        WHERE r."RULE_NAME" = ANY(v_names);
    END IF;

    UPDATE public."EXCEPTION" e
       SET "ASSIGN_TO_ID"  = v_user_id,
           "MODIFIED_DATE" = v_now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM public."RULE" r
        WHERE r."RULE_NAME" = ANY(v_names)
     );

    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
