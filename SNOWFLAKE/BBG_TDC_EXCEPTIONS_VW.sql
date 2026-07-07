-- BBG_TDC_EXCEPTIONS_VW: EXCEPTION rows for the 'Bloomberg Compare
-- Differences' RULE_CATALOG, plus the four RESULT_DATA-only JSON keys
-- exposed as their own columns.
--
-- RESULT_DATA is stored as VARCHAR; PARSE_JSON turns it into a VARIANT
-- so keys can be addressed with the ":" accessor. The three keys that
-- also exist on EXCEPTION (RULE_ID, ID_BB_GLOBAL, ISSUE_DESCRIPTION)
-- are intentionally omitted here so the EXCEPTION-side value wins.
--
-- The RESULT_DATA column itself is NOT projected — consumers of this
-- view already get the parsed JSON keys as their own columns, and the
-- raw blob is noise on the wire. If a caller needs the raw JSON, read
-- EXCEPTION directly.

CREATE OR REPLACE VIEW BBG_TDC_EXCEPTIONS_VW AS
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
       PARSE_JSON(e."RESULT_DATA"):"RULE_NAME"::VARCHAR     AS "RULE_NAME",
       PARSE_JSON(e."RESULT_DATA"):"ALADDIN_ID"::VARCHAR    AS "ALADDIN_ID",
       PARSE_JSON(e."RESULT_DATA"):"BBG_VALUE"::VARCHAR     AS "BBG_VALUE",
       PARSE_JSON(e."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR AS "ALADDIN_VALUE"
  FROM "EXCEPTION" e
  JOIN "RULE"          r  ON r."RULE_ID"          = e."RULE_ID"
  JOIN "RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
 WHERE rc."NAME" = 'Bloomberg Compare Differences';
