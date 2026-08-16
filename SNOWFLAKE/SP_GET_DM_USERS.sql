-- GET_DM_USERS ----------------------------------------------------------------
-- Feeds every "Assign To" dropdown surface — the per-row select in
-- the Exceptions grid, the Bulk Assign panel, and the assets grid.
-- Deliberately excludes ROLE IN ('IT_SUPPORT', 'IT_USER'): those
-- operators keep every DM_ADMIN gate on the frontend (Bulk Assign /
-- Bulk Status buttons visible, per-row Assign To editable) but
-- shouldn't be valid ASSIGNMENT TARGETS. "Unassigned" and every
-- other role (DM_ADMIN, DM_USER, NULL) pass through.
CREATE OR REPLACE PROCEDURE SP_GET_DM_USERS()
RETURNS TABLE("USER" VARCHAR, "ROLE" VARCHAR, "EMAIL" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "USER", "ROLE", "EMAIL"
        FROM "DM_USER"
        WHERE "ROLE" IS NULL OR "ROLE" NOT IN ('IT_SUPPORT', 'IT_USER')
        ORDER BY "ID" ASC
    );
    RETURN TABLE(res);
END;
$$;
