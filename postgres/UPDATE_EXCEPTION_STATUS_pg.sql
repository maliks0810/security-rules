DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATUS"(bigint, text);
DROP FUNCTION IF EXISTS public."SP_UPDATE_EXCEPTION_STATUS"(bigint, text, text, date);

-- Sets EXCEPTION.STATUS_ID for the row identified by p_exception_id,
-- resolving p_status_name against EXCEPTION_STATUS.NAME. Also bumps
-- MODIFIED_DATE / MODIFIED_BY. Returns 1 on success, 0 if the row or
-- the status name did not match, or if the caller tried to move the
-- row into "Suppress" without a SUPPRESS_DATE set (defence-in-depth
-- alongside the frontend guard).
--
-- Optional p_comments / p_suppress_date let the caller bundle a
-- pending comment + suppress date the operator just typed but hasn't
-- committed via the per-cell endpoints yet — needed because
-- CommentsCell only commits on blur and SuppressDateCell's separate
-- commit is async, so a status change fired immediately after would
-- otherwise race and hit the "blank" guard against a stale DB row.
--   NULL / omitted → leave the column alone (existing DB value stays).
--   Any non-null   → applied atomically inside this same UPDATE.
--
-- Side effect for 'Accept': the source row is snapshotted into
-- EXCEPTION_OVERRIDE in the same statement. EXCEPTION_ID is omitted so
-- the override's IDENTITY assigns its own key.
CREATE OR REPLACE FUNCTION public."SP_UPDATE_EXCEPTION_STATUS"(
    p_exception_id  bigint,
    p_status_name   text,
    p_comments      text DEFAULT NULL,
    p_suppress_date date DEFAULT NULL
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
               -- COMMENTS: apply the passed value when provided
               -- (non-null), else leave the existing DB value alone.
               -- Same NULL-vs-value convention as
               -- SP_UPDATE_BULK_STATUS.
               "COMMENTS"      = COALESCE(p_comments, "COMMENTS"),
               -- SUPPRESS_DATE: only 'Suppress' keeps a value. When
               -- p_suppress_date is passed and the target status is
               -- Suppress, use it; otherwise fall back to the
               -- existing DB value. Moving off Suppress (to New /
               -- Accept / Override / …) clears the date so the grid
               -- never shows a stale suppression next to a
               -- non-Suppress row.
               "SUPPRESS_DATE" = CASE
                                     WHEN p_status_name = 'Suppress'
                                         THEN COALESCE(p_suppress_date, "SUPPRESS_DATE")
                                     ELSE NULL
                                 END,
               -- OPEN_DATE ratchets when the row transitions TO 'New';
               -- otherwise the last-New date is preserved.
               "OPEN_DATE"     = CASE
                                     WHEN p_status_name = 'New'
                                         THEN (NOW() AT TIME ZONE 'UTC')::date
                                     ELSE "OPEN_DATE"
                                 END,
               -- CLOSE_DATE stamps today when the row is closed via a
               -- transition to 'Accept' or 'Research'. Any other
               -- transition (New / Suppress / Override / Complete)
               -- preserves the previous CLOSE_DATE.
               "CLOSE_DATE"    = CASE
                                     WHEN p_status_name IN ('Accept', 'Research')
                                         THEN (NOW() AT TIME ZONE 'UTC')::date
                                     -- Transitions to 'New' / 'Suppress'
                                     -- / 'Challenge' put the row back
                                     -- into an unresolved / pending
                                     -- state; the historical close date
                                     -- is no longer valid.
                                     WHEN p_status_name IN ('New', 'Suppress', 'Challenge')
                                         THEN NULL
                                     ELSE "CLOSE_DATE"
                                 END,
               "MODIFIED_DATE" = (NOW() AT TIME ZONE 'UTC'),
               "MODIFIED_BY"   = 'system'
         WHERE "EXCEPTION_ID" = p_exception_id
           AND EXISTS (
               SELECT 1 FROM public."EXCEPTION_STATUS"
                WHERE "NAME" = p_status_name
           )
           -- Guards check the *effective* value (passed param when
           -- present, else existing DB value) so a bundled comment /
           -- suppress date the operator just typed satisfies the rule
           -- without needing the per-cell commit to land first.
           AND NOT (p_status_name = 'Suppress'
                    AND COALESCE(p_suppress_date, "SUPPRESS_DATE") IS NULL)
           AND NOT (p_status_name <> 'New'
                    AND (COALESCE(p_comments, "COMMENTS") IS NULL
                         OR COALESCE(p_comments, "COMMENTS") = ''))
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
