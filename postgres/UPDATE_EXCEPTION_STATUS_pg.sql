DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATUS"(bigint, text);

-- Sets EXCEPTION.STATUS_ID for the row identified by p_exception_id,
-- resolving p_status_name against EXCEPTION_STATUS.NAME. Also bumps
-- MODIFIED_DATE / MODIFIED_BY. Returns 1 on success, 0 if the row or
-- the status name did not match, or if the caller tried to move the
-- row into "Suppress" without a SUPPRESS_DATE set (defence-in-depth
-- alongside the frontend guard).
--
-- Side effect for 'Accept': the source row is snapshotted into
-- EXCEPTION_OVERRIDE in the same statement. EXCEPTION_ID is omitted so
-- the override's IDENTITY assigns its own key.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_STATUS"(
    p_exception_id bigint,
    p_status_name  text
)
RETURNS integer
LANGUAGE sql
AS $$
    WITH updated AS (
        UPDATE public."EXCEPTION"
           SET "STATUS_ID"     = (
                   SELECT "EXCEPTION_STATUS_ID"
                   FROM public."EXCEPTION_STATUS"
                   WHERE "NAME" = p_status_name
                   LIMIT 1
               ),
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
           AND EXISTS (
               SELECT 1 FROM public."EXCEPTION_STATUS"
                WHERE "NAME" = p_status_name
           )
           AND NOT (p_status_name = 'Suppress' AND "SUPPRESS_DATE" IS NULL)
        -- RETURNING the whole row so the accept_snapshot CTE below can
        -- read the post-update state (STATUS_ID now = Accept's id).
        -- Reading from public."EXCEPTION" directly would see the CTE's
        -- pre-update snapshot in Postgres.
        RETURNING *
    ),
    accept_snapshot AS (
        INSERT INTO public."EXCEPTION_OVERRIDE" (
            "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
            "STATE_ID", "STATUS_ID", "COMMENTS", "EXCEPTION_TIME",
            "ISSUE_DESCRIPTION", "RESULT_DATA", "SUPPRESS_DATE",
            "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE",
            "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        )
        SELECT
            "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
            "STATE_ID", "STATUS_ID", "COMMENTS", "EXCEPTION_TIME",
            "ISSUE_DESCRIPTION", "RESULT_DATA", "SUPPRESS_DATE",
            "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE",
            "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        FROM updated
        WHERE p_status_name = 'Accept'
        RETURNING 1
    )
    -- Data-modifying CTEs (accept_snapshot) are executed to completion
    -- even when not referenced by the final SELECT, so the INSERT still
    -- runs. The row count comes from `updated`.
    SELECT COALESCE(COUNT(*), 0)::int FROM updated;
$$;
