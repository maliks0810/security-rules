-- SP_GET_SECURITY_GROUPS: the distinct SECURITY_GROUP values available
-- to pick from. Postgres mirror of
-- SNOWFLAKE/SP_GET_SECURITY_GROUPS.sql.
--
-- Sourced from SECURITY_CURRENT_VW rather than DIM_SECURITY directly so
-- the function follows whatever the view decides "current" means.
-- Blank / NULL groups are excluded - they are not selectable values.

DROP FUNCTION IF EXISTS public."SP_GET_SECURITY_GROUPS"();

CREATE OR REPLACE FUNCTION public."SP_GET_SECURITY_GROUPS"()
RETURNS TABLE("SECURITY_GROUP" text)
LANGUAGE sql
AS $$
    SELECT DISTINCT v."SECURITY_GROUP"::text
    FROM public."SECURITY_CURRENT_VW" v
    WHERE v."SECURITY_GROUP" IS NOT NULL
      AND btrim(v."SECURITY_GROUP") <> ''
    ORDER BY 1 ASC;
$$;
