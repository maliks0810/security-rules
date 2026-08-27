DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_ASSIGN"(text, text);
DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_ASSIGN"(text, text, boolean);
DROP FUNCTION IF EXISTS public."SP_UPDATE_BULK_ASSIGN"(text, text, text, boolean);

-- Bulk-assigns a user to an explicit set of EXCEPTION rows, named
-- outright by p_exception_ids - the rows the operator ticked in the
-- Exceptions grid's bulk-selection column, and the only rows whose
-- ASSIGN_TO_ID is touched.
--
-- p_rule_names is NOT a target set: it is the distinct set of rules
-- those selected rows belong to, and it drives ONLY the permanent
-- rule-level write:
--   FALSE (default) - no rule-level write at all. Only the selected
--                     EXCEPTION rows change.
--   TRUE            - UPDATE RULE.ASSIGN_TO_ID for every named rule.
--                     Exceptions created later inherit it because
--                     InsertExceptions stamps the rule default onto
--                     each new row as it is written.
-- An empty p_rule_names skips that write and still reassigns the
-- selected exceptions.
--
-- RULE_ASSIGN_OVERRIDE is neither written nor read anywhere any more:
-- the assignee resolves as COALESCE(e.ASSIGN_TO_ID, r.ASSIGN_TO_ID)
-- across every read function.
--
-- Both lists are plain comma-separated strings (matches the SNOWFLAKE
-- contract). Empty p_exception_ids / unknown p_assign_to -> 0-row
-- no-op. Returns the number of EXCEPTION rows updated.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_BULK_ASSIGN"(
    p_exception_ids text,
    p_rule_names   text,
    p_assign_to    text,
    p_is_permanent boolean DEFAULT false
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_user_id integer;
    v_now_ts  timestamp := (NOW() AT TIME ZONE 'UTC');
    v_names   text[];
    v_ids     bigint[];
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

    -- The selection is what gets reassigned, so an empty id list is the
    -- only fatal case here.
    IF p_exception_ids IS NULL OR p_exception_ids = '' THEN
        RETURN 0;
    END IF;

    -- Non-numeric tokens are dropped rather than raising: the client
    -- only ever sends digits, and a cast error would fail the whole
    -- batch over one malformed token.
    SELECT ARRAY(
        SELECT btrim(t.id)::bigint
        FROM unnest(string_to_array(p_exception_ids, ',')) AS t(id)
        WHERE btrim(t.id) ~ '^[0-9]+$'
    ) INTO v_ids;

    IF v_ids IS NULL OR array_length(v_ids, 1) IS NULL THEN
        RETURN 0;
    END IF;

    -- Trim + drop empty tokens so trailing / adjacent commas don't
    -- become empty rule-name lookups. Column alias `AS t(name)` is
    -- explicit - bare `unnest(...) AS t` gives column `unnest`, not `t`.
    SELECT ARRAY(
        SELECT btrim(t.name)
        FROM unnest(string_to_array(p_rule_names, ',')) AS t(name)
        WHERE btrim(t.name) <> ''
    ) INTO v_names;

    -- Rule-level write ONLY when the operator ticked Is Permanent.
    -- With Is Permanent ticked the UI forces every row selected and
    -- locks the checkboxes, so the EXCEPTION update below covers the
    -- whole grid; this rule write is what makes the assignment stick
    -- for rows created LATER, because InsertExceptions stamps
    -- RULE.ASSIGN_TO_ID onto each new exception as it is written.
    --
    -- An empty rule list is not fatal; it just means no rule-level
    -- write at all.
    IF p_is_permanent AND v_names IS NOT NULL AND array_length(v_names, 1) IS NOT NULL THEN
        -- RULE has no MODIFIED_DATE / MODIFIED_BY columns (see
        -- RULE_pg.sql), so only the assignee is set here.
        UPDATE public."RULE" r
           SET "ASSIGN_TO_ID" = v_user_id
         WHERE r."RULE_NAME" = ANY(v_names);
    END IF;

    UPDATE public."EXCEPTION" e
       SET "ASSIGN_TO_ID"  = v_user_id,
           "MODIFIED_DATE" = v_now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."EXCEPTION_ID" = ANY(v_ids);

    GET DIAGNOSTICS v_affected = ROW_COUNT;
    RETURN v_affected;
END;
$$;
