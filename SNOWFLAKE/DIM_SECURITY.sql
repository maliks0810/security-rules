-- DIM_SECURITY: one row per security the exception data references,
-- carrying its classification. ALADDIN_ID is the natural key and lines
-- up with EXCEPTION.ASSET_ID / EXCEPTION_HIST.ASSET_ID (both
-- VARCHAR(100)), so joins need no casting.
--
-- Exactly the three requested columns, with no CREATED_BY /
-- CREATED_DATE audit pair. Every other table here carries one, so this
-- is a deliberate departure rather than an oversight - add them if this
-- ever becomes operator-maintained rather than derived.

CREATE OR REPLACE TABLE DIM_SECURITY
(
    ALADDIN_ID      VARCHAR(100)
  , SECURITY_GROUP  VARCHAR(100)
  , SECURITY_TYPE   VARCHAR(100)
)
go

-- Populated from the distinct ASSET_IDs across BOTH exception tables,
-- not just the live one: EXCEPTION holds recent days while archived
-- days live in EXCEPTION_HIST, so seeding from EXCEPTION alone would
-- leave a historical-date view with rows whose security has no
-- dimension entry. Blank / NULL ids are excluded - they are not
-- securities.
--
-- SECURITY_GROUP and SECURITY_TYPE are seeded to the same constants for
-- every row, as specified. They are placeholders for real
-- classification data, not derived values.
INSERT INTO DIM_SECURITY (ALADDIN_ID, SECURITY_GROUP, SECURITY_TYPE)
SELECT a."ASSET_ID", 'ABS', 'AGENCY'
FROM (
    SELECT DISTINCT "ASSET_ID" FROM "EXCEPTION"
    UNION
    SELECT DISTINCT "ASSET_ID" FROM "EXCEPTION_HIST"
) a
WHERE a."ASSET_ID" IS NOT NULL
  AND TRIM(a."ASSET_ID") <> ''
go
