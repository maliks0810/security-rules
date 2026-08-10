DROP FUNCTION IF EXISTS public."SP_GET_DM_ROLE"(text);

-- Returns DM_USER.ROLE for the given display name. Callers (the
-- frontend gate) pass the current operator's DM_USER."USER" value —
-- resolved from Okta once integration lands, hard-coded pre-cutover —
-- and use the returned role to decide whether the Bulk Assign /
-- Bulk Status buttons are visible and whether the per-row Assign To
-- column is editable. Unknown / unassigned users return an empty row
-- so the caller can treat "no role" as the least-privileged default.
CREATE OR REPLACE FUNCTION public."SP_GET_DM_ROLE"(
    p_user text
)
RETURNS TABLE("ROLE" varchar)
LANGUAGE sql
AS $$
    SELECT "ROLE"
    FROM public."DM_USER"
    WHERE "USER" = p_user
    LIMIT 1;
$$;
