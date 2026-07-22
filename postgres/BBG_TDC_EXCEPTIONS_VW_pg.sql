-- BBG_TDC_EXCEPTIONS_VW: EXCEPTION rows for the 'Bloomberg Compare
-- Differences' RULE_CATALOG, plus the four RESULT_DATA-only JSON keys
-- exposed as their own columns.
--
-- RESULT_DATA is emitted by SP_RECON_BBG_COMPARE with seven keys:
--   RULE_NAME, ALADDIN_ID, ID_BB_GLOBAL, BBG_VALUE, ALADDIN_VALUE,
--   ISSUE_DESCRIPTION, RULE_ID.
-- Three overlap with EXCEPTION columns by name (RULE_ID, ID_BB_GLOBAL,
-- ISSUE_DESCRIPTION); those are intentionally omitted from the JSON
-- projection so the EXCEPTION-side value wins per spec.
--
-- The RESULT_DATA column itself is NOT projected — consumers already
-- get the parsed JSON keys as their own columns, and the raw blob is
-- noise on the wire. If a caller needs the raw JSON, read EXCEPTION.

DROP VIEW IF EXISTS public."BBG_TDC_EXCEPTIONS_VW";

CREATE VIEW public."BBG_TDC_EXCEPTIONS_VW" AS
SELECT e."EXCEPTION_ID",
       e."RULE_ID",
       e."ASSET_ID",
       e."EXCEPTION_DATE",
       e."ID_BB_GLOBAL",
       e."STATE_ID",
       e."STATUS_ID",
       e."COMMENTS",
       e."EXCEPTION_TIME",
       e."ISSUE_DESCRIPTION",
       e."SUPPRESS_DATE",
       e."ASSIGN_TO_ID",
       e."RESULT_TYPE_ID",
       e."CREATED_DATE",
       e."CREATED_BY",
       e."MODIFIED_DATE",
       e."MODIFIED_BY",
       (e."RESULT_DATA")::jsonb ->> 'RULE_NAME'     AS "RULE_NAME",
       (e."RESULT_DATA")::jsonb ->> 'ALADDIN_ID'    AS "ALADDIN_ID",
       (e."RESULT_DATA")::jsonb ->> 'BBG_VALUE'     AS "BBG_VALUE",
       (e."RESULT_DATA")::jsonb ->> 'ALADDIN_VALUE' AS "ALADDIN_VALUE"
  FROM public."EXCEPTION" e
  JOIN public."RULE"          r  ON r."RULE_ID"          = e."RULE_ID"
  JOIN public."RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
 WHERE rc."NAME" = 'Bloomberg Compare Differences';
