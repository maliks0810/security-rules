-- SP_GET_SECURITY_GROUPS: the distinct SECURITY_GROUP values available
-- to pick from, sourced from SECURITY_CURRENT_VW rather than
-- DIM_SECURITY directly so the procedure follows whatever the view
-- decides "current" means.
--
-- Blank / NULL groups are excluded - they are not selectable values,
-- and a dropdown entry with no label is unusable.

CREATE OR REPLACE PROCEDURE SP_GET_SECURITY_GROUPS()
RETURNS TABLE("SECURITY_GROUP" VARCHAR)
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT DISTINCT "SECURITY_GROUP"
        FROM "SECURITY_CURRENT_VW"
        WHERE "SECURITY_GROUP" IS NOT NULL
          AND TRIM("SECURITY_GROUP") <> ''
        ORDER BY "SECURITY_GROUP" ASC
    );
    RETURN TABLE(res);
END;
$$;
