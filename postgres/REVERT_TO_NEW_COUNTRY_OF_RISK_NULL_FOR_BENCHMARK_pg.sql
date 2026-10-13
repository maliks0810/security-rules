DROP FUNCTION IF EXISTS public."SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK"();

-- Country-Of-Risk-Null-For-Benchmark catalog-scoped revert workflow.
-- Three passes mirroring the Bloomberg SP:
--   Pass 1: non-New, non-Suppress, non-Hold, non-Override rows whose
--           asset still shows COUNTRY_OF_RISK_CODE IS NULL in
--           SECURITY_CURRENT_VW → revert.
--   Pass 2: expired Suppress OR Hold → revert, clear SUPPRESS_DATE.
--           Hold is treated identically to Suppress because applying
--           a Hold stamps SUPPRESS_DATE to T+2.
--   Pass 3: Override rows whose asset still shows COUNTRY_OF_RISK_CODE
--           IS NULL → revert.
-- No SECURITY_CURRENT_VW row for the ASSET_ID is treated as "not
-- null" (EXISTS fails) and does NOT revert.
CREATE OR REPLACE FUNCTION public."SP_REVERT_TO_NEW_COUNTRY_OF_RISK_NULL_FOR_BENCHMARK"()
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    v_today            date      := (NOW() AT TIME ZONE 'UTC')::date;
    v_now_ts           timestamp := (NOW() AT TIME ZONE 'UTC');
    v_suppress_id      integer;
    v_hold_id          integer;
    v_override_id      integer;
    v_null_affected    integer   := 0;
    v_expired_affected integer   := 0;
    v_override_affected integer  := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID"
      INTO v_suppress_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Suppress'
     LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID"
      INTO v_hold_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Hold'
     LIMIT 1;

    SELECT "EXCEPTION_STATUS_ID"
      INTO v_override_id
      FROM public."EXCEPTION_STATUS"
     WHERE "NAME" = 'Override'
     LIMIT 1;

    WITH scoped_rules AS (
        SELECT r."RULE_ID"
          FROM public."RULE" r
          JOIN public."RULE_CATALOG" rc
            ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
         WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
    ),
    null_upd AS (
        UPDATE public."EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
               "SUPPRESS_DATE" = NULL,
               "CLOSE_DATE"    = NULL,
               "MODIFIED_DATE" = v_now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID" <> 1
           AND (v_suppress_id IS NULL OR e."STATUS_ID" <> v_suppress_id)
           AND (v_hold_id     IS NULL OR e."STATUS_ID" <> v_hold_id)
           AND (v_override_id IS NULL OR e."STATUS_ID" <> v_override_id)
           AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
           AND EXISTS (
               SELECT 1
                 FROM public."SECURITY_CURRENT_VW" scv
                WHERE scv."ALADDIN_ID"           = e."ASSET_ID"
                  AND scv."COUNTRY_OF_RISK_CODE" IS NULL
           )
        RETURNING 1
    )
    SELECT COALESCE(COUNT(*), 0)::int INTO v_null_affected FROM null_upd;

    IF v_suppress_id IS NOT NULL OR v_hold_id IS NOT NULL THEN
        WITH scoped_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
        ),
        expired_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   "SUPPRESS_DATE" = NULL,
                   "CLOSE_DATE"    = NULL,
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE (
                     (v_suppress_id IS NOT NULL AND e."STATUS_ID" = v_suppress_id)
                     OR
                     (v_hold_id     IS NOT NULL AND e."STATUS_ID" = v_hold_id)
                   )
               AND e."SUPPRESS_DATE" IS NOT NULL
               AND e."SUPPRESS_DATE" < v_today
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_expired_affected FROM expired_upd;
    END IF;

    IF v_override_id IS NOT NULL THEN
        WITH scoped_rules AS (
            SELECT r."RULE_ID"
              FROM public."RULE" r
              JOIN public."RULE_CATALOG" rc
                ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             WHERE rc."NAME" = 'Country Of Risk Null For Benchmark'
        ),
        override_upd AS (
            UPDATE public."EXCEPTION" e
               SET "STATUS_ID"     = 1,
                   "CLOSE_DATE"    = NULL,
                   "SUPPRESS_DATE" = NULL,
                   "OPEN_DATE"     = COALESCE(e."OPEN_DATE", v_today),
                   "MODIFIED_DATE" = v_now_ts,
                   "MODIFIED_BY"   = 'system'
             WHERE e."STATUS_ID" = v_override_id
               AND e."RULE_ID" IN (SELECT "RULE_ID" FROM scoped_rules)
               AND EXISTS (
                   SELECT 1
                     FROM public."SECURITY_CURRENT_VW" scv
                    WHERE scv."ALADDIN_ID"           = e."ASSET_ID"
                      AND scv."COUNTRY_OF_RISK_CODE" IS NULL
               )
            RETURNING 1
        )
        SELECT COALESCE(COUNT(*), 0)::int INTO v_override_affected FROM override_upd;
    END IF;

    RETURN v_null_affected + v_expired_affected + v_override_affected;
END;
$$;
