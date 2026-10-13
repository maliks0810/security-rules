-- ID-BB-Company-Null-For-Benchmark catalog-scoped revert workflow.
-- Same shape as SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK;
-- the only differences are the procedure name, the catalog name, and
-- the SECURITY_CURRENT_VW column being null-checked (ID_BB_COMPANY).

CREATE OR REPLACE PROCEDURE SP_REVERT_TO_NEW_IDBBCOMPANY_NULL_FOR_BENCHMARK()
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    today             DATE          := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    now_ts            TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    suppress_id       NUMBER        := NULL;
    override_id       NUMBER        := NULL;
    null_affected     NUMBER        := 0;
    suppress_affected NUMBER        := 0;
    override_affected NUMBER        := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID" INTO :suppress_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Suppress'
    LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID" INTO :override_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Override'
    LIMIT 1;

    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = 1,
           "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
           "SUPPRESS_DATE" = NULL,
           "CLOSE_DATE"    = NULL,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE e."STATUS_ID" <> 1
       AND (:suppress_id IS NULL OR e."STATUS_ID" <> :suppress_id)
       AND (:override_id IS NULL OR e."STATUS_ID" <> :override_id)
       AND e."RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM "RULE" r
             JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
       )
       AND EXISTS (
           SELECT 1
             FROM TDC.SECURITY_CURRENT_VW scv
            WHERE scv."ALADDIN_ID"    = e."ASSET_ID"
              AND scv."ID_BB_COMPANY" IS NULL
       );
    null_affected := SQLROWCOUNT;

    IF (:suppress_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               "CLOSE_DATE"    = NULL,
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID"    = :suppress_id
           AND e."SUPPRESS_DATE" IS NOT NULL
           AND e."SUPPRESS_DATE" < :today
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
           );
        suppress_affected := SQLROWCOUNT;
    END IF;

    IF (:override_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "CLOSE_DATE"    = NULL,
               "SUPPRESS_DATE" = NULL,
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", :today),
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID" = :override_id
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'ID BB Company Null For Benchmark'
           )
           AND EXISTS (
               SELECT 1
                 FROM TDC.SECURITY_CURRENT_VW scv
                WHERE scv."ALADDIN_ID"    = e."ASSET_ID"
                  AND scv."ID_BB_COMPANY" IS NULL
           );
        override_affected := SQLROWCOUNT;
    END IF;

    RETURN null_affected + suppress_affected + override_affected;
END;
$$;
