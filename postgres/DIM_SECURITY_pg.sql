-- DIM_SECURITY: one row per security the exception data references,
-- carrying its classification. Postgres mirror of
-- SNOWFLAKE/DIM_SECURITY.sql.
--
-- ALADDIN_ID is the natural key and lines up with EXCEPTION.ASSET_ID /
-- EXCEPTION_HIST.ASSET_ID (both character varying(100)), so joins need
-- no casting.
--
-- Exactly the three requested columns, with no CREATED_BY /
-- CREATED_DATE audit pair - a deliberate departure from every other
-- table here.

DROP VIEW IF EXISTS public."SECURITY_CURRENT_VW";
DROP TABLE IF EXISTS public."DIM_SECURITY";

CREATE TABLE public."DIM_SECURITY"
(
    "ALADDIN_ID"     character varying(100)
  , "SECURITY_GROUP" character varying(100)
  , "SECURITY_TYPE"  character varying(100)
);

-- Populated from the distinct ASSET_IDs across BOTH exception tables,
-- not just the live one: EXCEPTION holds recent days while archived
-- days live in EXCEPTION_HIST, so seeding from EXCEPTION alone would
-- leave a historical-date view with rows whose security has no
-- dimension entry. Blank / NULL ids are excluded.
--
-- SECURITY_GROUP and SECURITY_TYPE are seeded to the same constants for
-- every row, as specified - placeholders for real classification data.
INSERT INTO public."DIM_SECURITY" ("ALADDIN_ID", "SECURITY_GROUP", "SECURITY_TYPE")
SELECT a."ASSET_ID", 'ABS', 'AGENCY'
FROM (
    SELECT DISTINCT "ASSET_ID" FROM public."EXCEPTION"
    UNION
    SELECT DISTINCT "ASSET_ID" FROM public."EXCEPTION_HIST"
) a
WHERE a."ASSET_ID" IS NOT NULL
  AND btrim(a."ASSET_ID") <> '';
