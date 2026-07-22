DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_HIST_DATES"();

-- Distinct EXCEPTION_DATEs present in EXCEPTION_HIST from the last 60 days
-- (UTC), most recent first. Powers the "DQM Date" dropdown in the LHS
-- sidebar — one entry per day regardless of how many BATCH_IDs that day
-- accumulated.
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_HIST_DATES"()
RETURNS TABLE("EXCEPTION_DATE" date)
LANGUAGE sql
AS $$
    SELECT DISTINCT "EXCEPTION_DATE"
      FROM public."EXCEPTION_HIST"
     WHERE "EXCEPTION_DATE" IS NOT NULL
       AND "EXCEPTION_DATE" >= ((NOW() AT TIME ZONE 'UTC')::date - INTERVAL '60 days')
     ORDER BY "EXCEPTION_DATE" DESC;
$$;
