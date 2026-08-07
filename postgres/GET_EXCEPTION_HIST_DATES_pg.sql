DROP FUNCTION IF EXISTS public."SP_GET_EXCEPTION_HIST_DATES"();

-- Returns every distinct EXCEPTION_DATE the DQM Date dropdown should
-- offer, most recent first:
--   * the single MAX EXCEPTION_DATE from the live EXCEPTION table
--     (the "current" pick for the top of the dropdown)
--   * every distinct EXCEPTION_DATE from EXCEPTION_HIST
-- Union deduplicates when the live max also appears in HIST. No
-- CURRENT_DATE / UTC math: the labels are driven entirely by what's
-- actually in the two tables, so the frontend doesn't drift from
-- server state when local vs UTC disagree.
CREATE OR REPLACE FUNCTION public."SP_GET_EXCEPTION_HIST_DATES"()
RETURNS TABLE("EXCEPTION_DATE" date)
LANGUAGE sql
AS $$
    SELECT d AS "EXCEPTION_DATE"
    FROM (
        SELECT MAX("EXCEPTION_DATE") AS d
          FROM public."EXCEPTION"
         WHERE "EXCEPTION_DATE" IS NOT NULL
        UNION
        SELECT DISTINCT "EXCEPTION_DATE" AS d
          FROM public."EXCEPTION_HIST"
         WHERE "EXCEPTION_DATE" IS NOT NULL
    ) x
    WHERE d IS NOT NULL
    ORDER BY d DESC;
$$;
