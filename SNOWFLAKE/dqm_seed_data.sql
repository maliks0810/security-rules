-- =============================================================================
-- dqm_seed_data.sql
--
-- Data-only companion to dqm_init.sql. Every INSERT / UPDATE / DELETE /
-- TRUNCATE that seeds or reshapes rows lives here so dqm_init.sql can
-- stay DDL-only (tables, views, procs).
--
-- RERUNNABILITY:
--   * Every top-level seed INSERT below runs against a freshly-created
--     table (each dqm_init.sql run drops and recreates the target via
--     CREATE OR REPLACE TABLE), so rerunning this file after a full
--     dqm_init.sql run is safe.
--   * Running this file WITHOUT first running dqm_init.sql on an
--     existing schema will duplicate rows (no ON CONFLICT / MERGE here).
--     Use only after a fresh dqm_init.sql run, or wrap individual
--     blocks in DELETE ... ; INSERT ... ; yourself.
--
-- ORDER MATTERS:
--   Lookups first, then DM_USER, then RULE_GROUP → RULE_CATALOG → RULE
--   so foreign-key subselects (e.g. "get RULE_GROUP_ID by name") land
--   after their target rows exist.
--
-- USAGE:
--   Run this whole file via Snowsight worksheet or:
--     snowsql -f SNOWFLAKE/dqm_seed_data.sql
--   The database/schema context is inherited from the caller's session —
--   USE DATABASE / USE SCHEMA yourself before running (or configure
--   default_database / default_schema on the SF role/user).
-- =============================================================================


-- =============================================================================
-- 1. LOOKUP SEEDS
-- =============================================================================

-- EXCEPTION_STATE ------------------------------------------------------------
INSERT INTO EXCEPTION_STATE (EXCEPTION_STATE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Pending',  10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'OnHold',   15, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Assigned', 20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'WorkedOn', 30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Complete', 40, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_STATUS -----------------------------------------------------------
-- Human triage workflow for individual exceptions (independent of the
-- rule-engine EXCEPTION_STATE lifecycle). Matches EXCEPTION_STATUS_pg.sql.
INSERT INTO EXCEPTION_STATUS (EXCEPTION_STATUS_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'New',       10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Accept',    20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Suppress',  30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Challenge', 40, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'Override',  50, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (6, 'Research',  60, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_TYPE --------------------------------------------------------------
INSERT INTO EXCEPTION_TYPE (EXCEPTION_TYPE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Security Setup',         10,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Trade Queue Management', 20,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Process/Workflow',       30,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Corporate Actions',      40,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'Analytics',              50,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (6, 'Portfolio',              110, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (7, 'Index',                  120, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_PRIORITY_TYPE -----------------------------------------------------
INSERT INTO EXCEPTION_PRIORITY_TYPE (EXCEPTION_PRIORITY_TYPE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'High',   10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Medium', 20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Low',    30, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_SEVERITY_TYPE -----------------------------------------------------
-- Seeded with the canonical severity categories used by the assets grid.
-- Adjust the VALUES list when business adds/renames severity buckets.
INSERT INTO EXCEPTION_SEVERITY_TYPE (EXCEPTION_SEVERITY_TYPE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Trading',          10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Compliance',       20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Reporting',        30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Settlement',       40, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'Forms',            50, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (6, 'Process/Workflow', 60, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (7, 'Analytics',        70, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (8, 'Performance',      80, CURRENT_USER(), CURRENT_TIMESTAMP());


-- =============================================================================
-- 2. OPERATIONAL SEEDS
-- =============================================================================

-- DM_USER ---------------------------------------------------------------------
-- Single INSERT with all three data columns per row — no follow-up
-- UPDATE sweep. Role semantics (kept alongside INIT_DM_USERS.sql):
--   DM_ADMIN   — unlocks Bulk Assign / Bulk Status + Assign To edit,
--                selectable as an assignment target.
--   IT_SUPPORT — same UI privileges as DM_ADMIN, filtered OUT of the
--                Assign To dropdown source (SP_GET_DM_USERS excludes
--                ROLE IN ('IT_SUPPORT','IT_USER')).
--   IT_USER    — mirrors IT_SUPPORT today, distinct role name so
--                future policy can diverge.
--   DM_USER    — least-privileged operator (default target).
--   NULL       — reserved for the "Unassigned" placeholder row.
-- Greg Killeen's email intentionally uses the long "Gregory" form —
-- every other row follows First.Last@tcw.com.
INSERT INTO DM_USER ("USER", "EMAIL", "ROLE") VALUES
    ('Unassigned',            NULL,                              NULL),
    ('Paul Cohen',             'Paul.Cohen@tcw.com',              'DM_USER'),
    ('Jake Rigney',            'Jake.Rigney@tcw.com',             'DM_USER'),
    ('Anush Safaryan',         'Anush.Safaryan@tcw.com',          'DM_USER'),
    ('Jimmy Fu',               'Jimmy.Fu@tcw.com',                'DM_USER'),
    ('Natasha Cabrera',        'Natasha.Cabrera@tcw.com',         'DM_USER'),
    ('Joann Banks',            'Joann.Banks@tcw.com',             'DM_ADMIN'),
    ('Naomi Lynch',            'Naomi.Lynch@tcw.com',             'DM_ADMIN'),
    ('Sumit Malik',            'Sumit.Malik@tcw.com',             'IT_SUPPORT'),
    ('Ethan Abraham',          'Ethan.Abraham@tcw.com',           'IT_SUPPORT'),
    ('Mukesh Verma',           'Mukesh.Verma@tcw.com',            'IT_SUPPORT'),
    ('Shrenik Doshi',          'Shrenik.Doshi@tcw.com',           'IT_SUPPORT'),
    ('Mark Segura',            'Mark.Segura@tcw.com',             'IT_SUPPORT'),
    ('Ken Desouza',            'Ken.Desouza@tcw.com',             'IT_SUPPORT'),
    ('Manish Ghayalod',        'Manish.Ghayalod@tcw.com',         'IT_USER'),
    ('Ari Novosyolok',         'Ari.Novosyolok@tcw.com',          'IT_USER'),
    ('Greg Killeen',           'Gregory.Killeen@tcw.com',         'IT_USER'),
    ('Jay Nolledo',            'Jay.Nolledo@tcw.com',             'IT_USER'),
    ('Bruce Pople',            'Bruce.Pople@tcw.com',             'IT_USER'),
    ('Melissa Stolfi',         'Melissa.Stolfi@tcw.com',          'IT_USER'),
    ('Sidharth Joshi',         'Sidharth.Joshi@tcw.com',          'IT_USER'),
    ('Prasanna Ramamoorthy',   'Prasanna.Ramamoorthy@tcw.com',    'IT_USER');

-- RULE_GROUP ------------------------------------------------------------------
INSERT INTO RULE_GROUP (NAME, DESCRIPTION, FLAG_STATUS_VISIBLE, FLAG_COMMENTS_VISIBLE, FLAG_SUPPRESS_DATE, FLAG_ASSIGN_TO_VISIBLE, CREATED_DATE, CREATED_BY) VALUES
    ('Security Master', 'Security Master', TRUE, TRUE, TRUE, TRUE, CURRENT_TIMESTAMP(), CURRENT_USER());

-- RULE_CATALOG ----------------------------------------------------------------
INSERT INTO RULE_CATALOG (NAME, DESCRIPTION, RULE_GROUP_ID, RULE_CATALOG_SOURCE, RULE_CATALOG_TYPE, RULE_CATALOG_CONNECTION, REVERT_TO_NEW_CRITERIA, CREATED_DATE, CREATED_BY)
SELECT
    'Bloomberg Compare Differences',
    'Bloomberg Compare Differences',
    (SELECT RULE_GROUP_ID FROM RULE_GROUP WHERE NAME = 'Security Master'),
    -- ${ALADDIN_ID} isn't a built-in placeholder (only ${ASSET_ID},
    -- ${ID_BB_GLOBAL}, ${IS_REFRESH} are). The leftover-sweep in
    -- resolveRuleCommand lands it as NULL unless a caller passes
    -- ?param_ALADDIN_ID=…; ${RULE_NAME} auto-populates only when
    -- rule_type=RULE.
    'CALL SP_RECON_BBG_TDC(${ALADDIN_ID}, ${ID_BB_GLOBAL}, ${RULE_NAME}, ${IS_REFRESH})',
    'SQL',
    'DE_SNOWFLAKE',
    'SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES',
    CURRENT_TIMESTAMP(),
    CURRENT_USER();

-- RULE ------------------------------------------------------------------------
-- Every INSERT here supplies ASSIGN_TO_ID = 2 (Paul Cohen — the primary
-- assignee seeded in DM_USER above). RULE.ASSIGN_TO_ID also has
-- DEFAULT 2 in dqm_init.sql, but we set it explicitly so the value
-- stays visible in the seed data and easy to override per rule.
INSERT INTO RULE (RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE, EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID, EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, ASSIGN_TO_ID, CREATED_BY, CREATED_DATE)
SELECT
    (SELECT RULE_CATALOG_ID FROM RULE_CATALOG WHERE NAME = 'Bloomberg Compare Differences'),
    'RULE_DM_BBG_MATURITY_DATE',
    'Compares Maturity Date between Bloomberg and Aladdin',
    1, 1, 1, 1, 2, 1,
    2,
    CURRENT_USER(), CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9);

INSERT INTO RULE (RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE, EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID, EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, ASSIGN_TO_ID, CREATED_BY, CREATED_DATE)
SELECT
    (SELECT RULE_CATALOG_ID FROM RULE_CATALOG WHERE NAME = 'Bloomberg Compare Differences'),
    'RULE_DM_BBG_REGISTRATION',
    'Compares Registration between Bloomberg and Aladdin',
    1, 1, 1, 1, 2, 1,
    2,
    CURRENT_USER(), CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9);

-- Production rule names (DM_BBG_* family). All map to the same catalog
-- (Bloomberg Compare Differences = RULE_CATALOG_ID 1 from the seed above).
-- Source: SNOWFLAKE/INSERT_RULES.sql -- keep this block in sync if rules
-- are added/removed there.
INSERT INTO RULE (
    RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE,
    EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID,
    EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, ASSIGN_TO_ID, CREATED_BY, CREATED_DATE
)
VALUES
    (1, 'DM_BBG_ACCRUAL_DT',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_ADC_TICKER',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BARC_LVL_1',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BARC_LVL_2',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BARC_LVL_3',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BARC_LVL_4',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BOND_TYPE_ABS',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BOND_TYPE_CMBS',                   NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BOND_TYPE_CMO_AGENY',              NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_BOND_TYPE_CMO_NON_AGENCY',         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CALC_TYP',                         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CALL_PUT_SINK',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_COMPOUNDING_INTEREST_INDICATOR',   NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CORP_GOVT_CLASS',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_COUNTRY',                          NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CPN_FREQ',                         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CPN_TYP',                          NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CRNCY',                            NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_CUR_CPN',                          NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_DAY_CONV',                         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_DEAL_AMT',                         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_DEAL_COLLATERAL',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_DUMMY_ID_TO_CUSIP',                NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_FACTOR',                           NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_FIRST_CPN_DT',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_FIRST_PRIN_DT',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_GLOBAL_FACILITY_AMT',              NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_INACTIVE_BANK_LOAN',               NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_ISSUER_LEI',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_LEAD_MGR',                         NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_LIEN_TYPE',                        NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_LOAN_FACILITY',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MATURITY_DT',                      NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_DEAL_NAME',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_FIRST_RST_DT',                 NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_IS_PAID_OFF',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_LIFE_CAP',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_LIFE_FLOOR',                   NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_NOTL_PRINC_FLAG',              NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MTG_PAY_DELAY',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_MUNI_TAX_CODE',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_NON_TBA_MIN_INCREMENT',            NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_NON_TBA_MIN_TRD_SIZE',             NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_PMT_CALENDAR',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_PRIN_FREQ',                        NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_REFERENCE_INDEX',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_REG_RIGHTS',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_REGISTRATION',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_REREMIC',                          NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RESET_IDX',                        NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_DBRS_LT',                      NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_FITCH_LT',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_FITCH_ST',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_KROLL_LT',                     NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_MOODYS_LT',                    NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_RTG_SNP_LT',                       NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_SEC_GROUP_TYPE',                   NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_STRUCTURE',                        NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_TICKER',                           NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_USE_OF_PROCEEDS',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_BBG_WHEN_ISSUED',                      NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_RTG_FORM_REVIEW',                      NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP()),
    (1, 'DM_TDC_COUNTRY_OF_RISK',                  NULL, 1, 1, 1, 1, 1, 1, 2, 'SYSTEM', CURRENT_TIMESTAMP());


-- =============================================================================
-- 3. MIGRATION SCRIPTS (one-time — DO NOT include in repeated rerun)
-- =============================================================================
-- These INSERT...SELECT scripts copy data from one table to another.
-- Rerunning them duplicates rows. Uncomment + run manually only when needed.

/*
-- Copy EXCEPTION snapshot into EXCEPTION_HIST.
INSERT INTO DATA_QUALITY.EXCEPTION_HIST (
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATE_ID, COMMENTS, EXCEPTION_TIME, ISSUE_DESCRIPTION,
    RESULT_DATA, SUPPRESS_DATE, ASSIGN_TO_ID, RESULT_TYPE_ID,
    CREATED_DATE, CREATED_BY, MODIFIED_DATE, MODIFIED_BY
)
SELECT
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATE_ID, COMMENTS, EXCEPTION_TIME, ISSUE_DESCRIPTION,
    RESULT_DATA, SUPPRESS_DATE, ASSIGN_TO_ID, RESULT_TYPE_ID,
    CREATED_DATE, CREATED_BY, MODIFIED_DATE, MODIFIED_BY
FROM DATA_QUALITY.EXCEPTION;


-- Initial backfill from legacy SECURITY_EXCEPTION (kept for reference; the
-- SECURITY_EXCEPTION table itself is no longer maintained here).
INSERT INTO DATA_QUALITY.EXCEPTION (
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATE_ID, EXCEPTION_TIME, ISSUE_DESCRIPTION, ASSIGN_TO_ID,
    RESULT_TYPE_ID, CREATED_DATE, CREATED_BY
)
SELECT
    SECURITY_EXCEPTION_ID,
    RULE_ID,
    ASSET_ID,
    TO_DATE(RUN_DATE),
    ID_BB_GLOBAL,
    EXCEPTION_STATUS_ID,
    RUN_DATE,
    ISSUE_DESCRIPTION,
    ASSIGN_TO_ID,
    RESULT_TYPE_ID,
    CREATED_DATE,
    CREATED_BY
FROM DATA_QUALITY.SECURITY_EXCEPTION;
*/

-- End of dqm_seed_data.sql
