-- Distinct EXCEPTION_DATEs from EXCEPTION_HIST within the last 60 days
-- (UTC), most recent first. Powers the "DQM Date" dropdown in the LHS
-- sidebar — one entry per day regardless of how many BATCH_IDs that day
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
        SELECT DISTINCT "EXCEPTION_DATE"
          FROM "EXCEPTION_HIST"
         WHERE "EXCEPTION_DATE" IS NOT NULL
           AND "EXCEPTION_DATE" >= DATEADD(day, -60, TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)))
         ORDER BY "EXCEPTION_DATE" DESC
    );
    RETURN TABLE(res);
END;
$$;
