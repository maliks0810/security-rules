-- Bulk seed of the 62 DM_BBG_* production rules into public."RULE".
-- Idempotent: each VALUES row is only inserted when no row with that
-- RULE_NAME already exists. Reruns are safe, and the demo seeds
-- (RULE_DM_BBG_MATURITY_DATE, RULE_DM_BBG_REGISTRATION) are preserved.
--
-- Mirror of SNOWFLAKE/INSERT_RULES.sql. The Snowflake variant uses
-- TRUNCATE + plain INSERT VALUES because it is run standalone; the
-- Postgres variant uses WHERE NOT EXISTS so it can be applied on top of
-- an already-seeded RULE table without disturbing existing rows.

INSERT INTO public."RULE" (
    "RULE_CATALOG_ID", "RULE_NAME", "RULE_DESCRIPTION", "IS_ACTIVE",
    "EXCEPTION_TYPE_ID", "EXCEPTION_PROCESS_TYPE_ID", "EXCEPTION_SEVERITY_TYPE_ID",
    "EXCEPTION_PRIORITY_TYPE_ID", "EXCEPTION_SOURCE", "CREATED_BY", "CREATED_DATE"
)
SELECT v.rule_catalog_id, v.rule_name, v.rule_description, v.is_active,
       v.exception_type_id, v.exception_process_type_id, v.exception_severity_type_id,
       v.exception_priority_type_id, v.exception_source, v.created_by, v.created_date
FROM (VALUES
    (1, 'DM_BBG_ACCRUAL_DT',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_ADC_TICKER',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BARC_LVL_1',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BARC_LVL_2',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BARC_LVL_3',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BARC_LVL_4',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BOND_TYPE_ABS',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BOND_TYPE_CMBS',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BOND_TYPE_CMO_AGENY',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_BOND_TYPE_CMO_NON_AGENCY',         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CALC_TYP',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CALL_PUT_SINK',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_COMPOUNDING_INTEREST_INDICATOR',   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CORP_GOVT_CLASS',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_COUNTRY',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CPN_FREQ',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CPN_TYP',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CRNCY',                            NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_CUR_CPN',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_DAY_CONV',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_DEAL_AMT',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_DEAL_COLLATERAL',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_DUMMY_ID_TO_CUSIP',                NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_FACTOR',                           NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_FIRST_CPN_DT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_FIRST_PRIN_DT',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_GLOBAL_FACILITY_AMT',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_INACTIVE_BANK_LOAN',               NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_ISSUER_LEI',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_LEAD_MGR',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_LIEN_TYPE',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_LOAN_FACILITY',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MATURITY_DT',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_DEAL_NAME',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_FIRST_RST_DT',                 NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_IS_PAID_OFF',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_LIFE_CAP',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_LIFE_FLOOR',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_NOTL_PRINC_FLAG',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MTG_PAY_DELAY',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_MUNI_TAX_CODE',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_NON_TBA_MIN_INCREMENT',            NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_NON_TBA_MIN_TRD_SIZE',             NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_PMT_CALENDAR',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_PRIN_FREQ',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_REFERENCE_INDEX',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_REG_RIGHTS',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_REGISTRATION',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_REREMIC',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RESET_IDX',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_DBRS_LT',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_FITCH_LT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_FITCH_ST',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_KROLL_LT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_MOODYS_LT',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_RTG_SNP_LT',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_SEC_GROUP_TYPE',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_STRUCTURE',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_TICKER',                           NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_USE_OF_PROCEEDS',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_BBG_WHEN_ISSUED',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_RTG_FORM_REVIEW',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp),
    (1, 'DM_TDC_COUNTRY_OF_RISK',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP::timestamp)
) AS v(
    rule_catalog_id, rule_name, rule_description, is_active,
    exception_type_id, exception_process_type_id, exception_severity_type_id,
    exception_priority_type_id, exception_source, created_by, created_date
)
WHERE NOT EXISTS (
    SELECT 1 FROM public."RULE" r WHERE r."RULE_NAME" = v.rule_name
);
