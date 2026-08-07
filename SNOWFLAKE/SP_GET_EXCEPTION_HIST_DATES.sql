-- Distinct EXCEPTION_DATEs from EXCEPTION_HIST within the last 60 days
-- (UTC), most recent first. Powers the "DQM Date" dropdown in the LHS
-- sidebar â€” one entry per day regardless of how many BATCH_IDs that day
-- accumulated.

CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_HIST_DATES()
RETURNS TABLE("EXCEPTION_DATE" DATE)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT d AS "EXCEPTION_DATE"
        FROM (
            SELECT MAX("EXCEPTION_DATE") AS d
              FROM "EXCEPTION"
             WHERE "EXCEPTION_DATE" IS NOT NULL
            UNION
            SELECT DISTINCT "EXCEPTION_DATE" AS d
              FROM "EXCEPTION_HIST"
             WHERE "EXCEPTION_DATE" IS NOT NULL
        ) x
        WHERE d IS NOT NULL
        ORDER BY d DESC
    );
    RETURN TABLE(res);
END;
$$;
