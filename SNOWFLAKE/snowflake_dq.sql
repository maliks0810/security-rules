-- =============================================================================
-- snowflake_dq.sql
--
-- Combined Snowflake setup for the security-rules / DQM application.
-- Database: TCW_CORE_DEV, Schema: DATA_QUALITY.
-- This is the canonical "fresh environment" script â€” running it brings the
-- DATA_QUALITY schema to the objects + seed data the Go service expects.
--
-- RERUNNABILITY:
--   * Every object uses CREATE OR REPLACE â€” tables, views, procedures.
--   * Lookup AND operational tables (DM_USER, RULE_GROUP, RULE_CATALOG, RULE,
--     EXCEPTION, EXCEPTION_HIST, EXCEPTION_STATE, EXCEPTION_TYPE,
--     EXCEPTION_PRIORITY_TYPE, EXCEPTION_SEVERITY_TYPE) are dropped and
--     recreated on each run, then re-seeded from the literal VALUES in
--     this script. Running this file destroys existing row data in those
--     tables â€” that is the intended semantic for repeatable environment
--     setup.
--   * If you need to preserve production data on a given table, comment
--     that table's CREATE OR REPLACE block before running the script.
--
-- MAINTAINING THIS FILE:
--   When you add, update, or drop a Snowflake object referenced by
--   security-rules, also update the matching section here. The individual
--   SNOWFLAKE/<name>.sql files are kept as per-object references, but this
--   combined script is the source of truth for setting up a new environment.
--   Sections are ordered to respect dependencies:
--     1. Lookup tables   2. Data tables   3. Views   4. Procedures
--
-- USAGE:
--   Run this whole file via Snowsight worksheet or:
--     snowsql -f SNOWFLAKE/snowflake_dq.sql
--   The database/schema context is set by the two USE statements below.
-- =============================================================================

USE DATABASE TCW_CORE_DEV;
USE SCHEMA DATA_QUALITY;


-- =============================================================================
-- 1. LOOKUP TABLES (seeded, idempotent via CREATE OR REPLACE)
-- =============================================================================

-- EXCEPTION_STATE ------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_STATE (
    EXCEPTION_STATE_ID INT,
    NAME                VARCHAR(100),
    SORT_ORDER          INT,
    CREATED_BY          VARCHAR(100),
    CREATED_DATE        TIMESTAMP_NTZ(9)
);

INSERT INTO EXCEPTION_STATE (EXCEPTION_STATE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Pending',  10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'OnHold',   15, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Assigned', 20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'WorkedOn', 30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Complete', 40, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_STATUS -----------------------------------------------------------
-- Human triage workflow for individual exceptions (independent of the
-- rule-engine EXCEPTION_STATE lifecycle). Matches EXCEPTION_STATUS_pg.sql.
CREATE OR REPLACE TABLE EXCEPTION_STATUS (
    EXCEPTION_STATUS_ID INT,
    NAME                VARCHAR(100),
    SORT_ORDER          INT,
    CREATED_BY          VARCHAR(100),
    CREATED_DATE        TIMESTAMP_NTZ(9)
);

INSERT INTO EXCEPTION_STATUS (EXCEPTION_STATUS_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'New',       10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Accept',    20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Suppress',  30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Challenge', 40, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'Override',  50, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (6, 'Research',  60, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_TYPE --------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_TYPE (
    EXCEPTION_TYPE_ID INT,
    NAME              VARCHAR(100),
    SORT_ORDER        INT,
    CREATED_BY        VARCHAR(100),
    CREATED_DATE      TIMESTAMP_NTZ(9)
);

INSERT INTO EXCEPTION_TYPE (EXCEPTION_TYPE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Security Setup',         10,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Trade Queue Management', 20,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Process/Workflow',       30,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Corporate Actions',      40,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'Analytics',              50,  CURRENT_USER(), CURRENT_TIMESTAMP()),
    (6, 'Portfolio',              110, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (7, 'Index',                  120, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_PRIORITY_TYPE -----------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_PRIORITY_TYPE (
    EXCEPTION_PRIORITY_TYPE_ID INT,
    NAME                       VARCHAR(100),
    SORT_ORDER                 INT,
    CREATED_BY                 VARCHAR(100),
    CREATED_DATE               TIMESTAMP_NTZ(9)
);

INSERT INTO EXCEPTION_PRIORITY_TYPE (EXCEPTION_PRIORITY_TYPE_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'High',   10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Medium', 20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'Low',    30, CURRENT_USER(), CURRENT_TIMESTAMP());

-- EXCEPTION_SEVERITY_TYPE -----------------------------------------------------
-- Seeded with the canonical severity categories used by the assets grid.
-- Adjust the VALUES list when business adds/renames severity buckets.
CREATE OR REPLACE TABLE EXCEPTION_SEVERITY_TYPE (
    EXCEPTION_SEVERITY_TYPE_ID INT,
    NAME                       VARCHAR(100),
    SORT_ORDER                 INT,
    CREATED_BY                 VARCHAR(100),
    CREATED_DATE               TIMESTAMP_NTZ(9)
);

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
-- 2. OPERATIONAL DATA TABLES (CREATE OR REPLACE â€” resets data on rerun)
-- =============================================================================

-- DM_USER ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DM_USER (
    ID   NUMBER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    "USER" VARCHAR(100) NOT NULL
);

INSERT INTO DM_USER ("USER") VALUES
    ('Unassigned'),
    ('Paul Cohen'),
    ('Jake Rigney'),
    ('Anush Safaryan'),
    ('Jimmy Fu'),
    ('Natasha Cabrera');

-- RULE_GROUP ------------------------------------------------------------------
CREATE OR REPLACE TABLE RULE_GROUP (
    RULE_GROUP_ID          NUMBER(38,0) IDENTITY(1,1) PRIMARY KEY,
    NAME                   VARCHAR(100),
    DESCRIPTION            VARCHAR(512),
    FLAG_STATUS_VISIBLE    BOOLEAN DEFAULT FALSE,
    FLAG_COMMENTS_VISIBLE  BOOLEAN DEFAULT FALSE,
    FLAG_SUPPRESS_DATE     BOOLEAN DEFAULT FALSE,
    FLAG_ASSIGN_TO_VISIBLE BOOLEAN DEFAULT FALSE,
    CREATED_DATE           TIMESTAMP_NTZ(9),
    CREATED_BY             VARCHAR(100)
);

INSERT INTO RULE_GROUP (NAME, DESCRIPTION, FLAG_STATUS_VISIBLE, FLAG_COMMENTS_VISIBLE, FLAG_SUPPRESS_DATE, FLAG_ASSIGN_TO_VISIBLE, CREATED_DATE, CREATED_BY) VALUES
    ('Security Master', 'Security Master', TRUE, TRUE, TRUE, TRUE, CURRENT_TIMESTAMP(), CURRENT_USER());

-- RULE_CATALOG ----------------------------------------------------------------
CREATE OR REPLACE TABLE RULE_CATALOG (
    RULE_CATALOG_ID         NUMBER(38,0) IDENTITY(1,1) PRIMARY KEY,
    NAME                    VARCHAR(100),
    DESCRIPTION             VARCHAR(512),
    RULE_GROUP_ID           NUMBER(38,0),
    RULE_CATALOG_SOURCE     VARCHAR(4096),
    RULE_CATALOG_TYPE       VARCHAR(100),
    RULE_CATALOG_CONNECTION VARCHAR(1000),
    CREATED_DATE            TIMESTAMP_NTZ(9),
    CREATED_BY              VARCHAR(100)
);

INSERT INTO RULE_CATALOG (NAME, DESCRIPTION, RULE_GROUP_ID, RULE_CATALOG_SOURCE, RULE_CATALOG_TYPE, RULE_CATALOG_CONNECTION, CREATED_DATE, CREATED_BY)
SELECT
    'Bloomberg Compare Differences',
    'Bloomberg Compare Differences',
    (SELECT RULE_GROUP_ID FROM RULE_GROUP WHERE NAME = 'Security Master'),
    'CALL SP_RECON_BBG_COMPARE(${ASSET_ID}, ${ID_BB_GLOBAL})',
    'SQL',
    'DE_SNOWFLAKE',
    CURRENT_TIMESTAMP(),
    CURRENT_USER();

-- RULE ------------------------------------------------------------------------
CREATE OR REPLACE TABLE RULE (
    RULE_ID                    NUMBER IDENTITY(1,1) PRIMARY KEY,
    RULE_CATALOG_ID            INT NULL,
    RULE_NAME                  VARCHAR(100) NULL,
    RULE_DESCRIPTION           VARCHAR(512) NULL,
    IS_ACTIVE                  NUMBER(38,0) NULL,
    EXCEPTION_TYPE_ID          NUMBER(38,0) NULL,
    EXCEPTION_PROCESS_TYPE_ID  NUMBER NULL,
    EXCEPTION_SEVERITY_TYPE_ID NUMBER NULL,
    EXCEPTION_PRIORITY_TYPE_ID NUMBER NULL,
    EXCEPTION_SOURCE           NUMBER NULL,
    CREATED_BY                 VARCHAR(100) NULL,
    CREATED_DATE               TIMESTAMP_NTZ(9) NULL
);

INSERT INTO RULE (RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE, EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID, EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, CREATED_BY, CREATED_DATE)
SELECT
    (SELECT RULE_CATALOG_ID FROM RULE_CATALOG WHERE NAME = 'Bloomberg Compare Differences'),
    'RULE_DM_BBG_MATURITY_DATE',
    'Compares Maturity Date between Bloomberg and Aladdin',
    1, 1, 1, 1, 2, 1,
    CURRENT_USER(), CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9);

INSERT INTO RULE (RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE, EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID, EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, CREATED_BY, CREATED_DATE)
SELECT
    (SELECT RULE_CATALOG_ID FROM RULE_CATALOG WHERE NAME = 'Bloomberg Compare Differences'),
    'RULE_DM_BBG_REGISTRATION',
    'Compares Registration between Bloomberg and Aladdin',
    1, 1, 1, 1, 2, 1,
    CURRENT_USER(), CURRENT_TIMESTAMP()::TIMESTAMP_NTZ(9);

-- Production rule names (DM_BBG_* family). All map to the same catalog
-- (Bloomberg Compare Differences = RULE_CATALOG_ID 1 from the seed above).
-- Source: SNOWFLAKE/INSERT_RULES.sql -- keep this block in sync if rules
-- are added/removed there.
INSERT INTO RULE (
    RULE_CATALOG_ID, RULE_NAME, RULE_DESCRIPTION, IS_ACTIVE,
    EXCEPTION_TYPE_ID, EXCEPTION_PROCESS_TYPE_ID, EXCEPTION_SEVERITY_TYPE_ID,
    EXCEPTION_PRIORITY_TYPE_ID, EXCEPTION_SOURCE, CREATED_BY, CREATED_DATE
)
VALUES
    (1, 'DM_BBG_ACCRUAL_DT',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_ADC_TICKER',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BARC_LVL_1',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BARC_LVL_2',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BARC_LVL_3',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BARC_LVL_4',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BOND_TYPE_ABS',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BOND_TYPE_CMBS',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BOND_TYPE_CMO_AGENY',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_BOND_TYPE_CMO_NON_AGENCY',         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CALC_TYP',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CALL_PUT_SINK',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_COMPOUNDING_INTEREST_INDICATOR',   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CORP_GOVT_CLASS',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_COUNTRY',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CPN_FREQ',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CPN_TYP',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CRNCY',                            NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_CUR_CPN',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_DAY_CONV',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_DEAL_AMT',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_DEAL_COLLATERAL',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_DUMMY_ID_TO_CUSIP',                NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_FACTOR',                           NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_FIRST_CPN_DT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_FIRST_PRIN_DT',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_GLOBAL_FACILITY_AMT',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_INACTIVE_BANK_LOAN',               NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_ISSUER_LEI',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_LEAD_MGR',                         NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_LIEN_TYPE',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_LOAN_FACILITY',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MATURITY_DT',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_DEAL_NAME',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_FIRST_RST_DT',                 NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_IS_PAID_OFF',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_LIFE_CAP',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_LIFE_FLOOR',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_NOTL_PRINC_FLAG',              NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MTG_PAY_DELAY',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_MUNI_TAX_CODE',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_NON_TBA_MIN_INCREMENT',            NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_NON_TBA_MIN_TRD_SIZE',             NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_PMT_CALENDAR',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_PRIN_FREQ',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_REFERENCE_INDEX',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_REG_RIGHTS',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_REGISTRATION',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_REREMIC',                          NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RESET_IDX',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_DBRS_LT',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_FITCH_LT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_FITCH_ST',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_KROLL_LT',                     NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_MOODYS_LT',                    NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_RTG_SNP_LT',                       NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_SEC_GROUP_TYPE',                   NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_STRUCTURE',                        NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_TICKER',                           NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_USE_OF_PROCEEDS',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_BBG_WHEN_ISSUED',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_RTG_FORM_REVIEW',                      NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP),
    (1, 'DM_TDC_COUNTRY_OF_RISK',                  NULL, 1, 1, 1, 1, 1, 1, 'SYSTEM', CURRENT_TIMESTAMP);

-- EXCEPTION -------------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION (
    EXCEPTION_ID      NUMBER IDENTITY(1000000,1) PRIMARY KEY,
    RULE_ID           INT,
    ASSET_ID          VARCHAR(100),
    EXCEPTION_DATE    DATE,
    ID_BB_GLOBAL      VARCHAR(15),
    STATE_ID         INT,
    STATUS_ID         INT DEFAULT 1,
    COMMENTS          VARCHAR(2048),
    EXCEPTION_TIME    TIMESTAMP_NTZ(9),
    ISSUE_DESCRIPTION VARCHAR(512),
    RESULT_DATA       VARCHAR,
    SUPPRESS_DATE     DATE,
    ASSIGN_TO_ID      INT,
    RESULT_TYPE_ID    INT,
    CREATED_DATE      TIMESTAMP_NTZ(9),
    CREATED_BY        VARCHAR(100),
    MODIFIED_DATE     TIMESTAMP_NTZ(9),
    MODIFIED_BY       VARCHAR(100)
);

-- EXCEPTION_HIST --------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_HIST (
    EXCEPTION_ID      INT,
    RULE_ID           INT,
    ASSET_ID          VARCHAR(100),
    EXCEPTION_DATE    DATE,
    BATCH_ID          NUMBER,
    ID_BB_GLOBAL      VARCHAR(15),
    STATE_ID         INT,
    STATUS_ID         INT,
    COMMENTS          VARCHAR(2048),
    EXCEPTION_TIME    TIMESTAMP_NTZ(9),
    ISSUE_DESCRIPTION VARCHAR(512),
    RESULT_DATA       VARCHAR,
    SUPPRESS_DATE     DATE,
    ASSIGN_TO_ID      INT,
    RESULT_TYPE_ID    INT,
    CREATED_DATE      TIMESTAMP_NTZ(9),
    CREATED_BY        VARCHAR(100),
    MODIFIED_DATE     TIMESTAMP_NTZ(9),
    MODIFIED_BY       VARCHAR(100)
);

-- EXCEPTION_OVERRIDE ----------------------------------------------------------
-- Mirrors EXCEPTION exactly; used to persist manual overrides for exceptions.
CREATE OR REPLACE TABLE EXCEPTION_OVERRIDE (
    EXCEPTION_ID      NUMBER IDENTITY(1000000,1) PRIMARY KEY,
    RULE_ID           INT,
    ASSET_ID          VARCHAR(100),
    EXCEPTION_DATE    DATE,
    ID_BB_GLOBAL      VARCHAR(15),
    STATE_ID         INT,
    STATUS_ID         INT DEFAULT 1,
    COMMENTS          VARCHAR(2048),
    EXCEPTION_TIME    TIMESTAMP_NTZ(9),
    ISSUE_DESCRIPTION VARCHAR(512),
    RESULT_DATA       VARCHAR,
    SUPPRESS_DATE     DATE,
    ASSIGN_TO_ID      INT,
    RESULT_TYPE_ID    INT,
    CREATED_DATE      TIMESTAMP_NTZ(9),
    CREATED_BY        VARCHAR(100),
    MODIFIED_DATE     TIMESTAMP_NTZ(9),
    MODIFIED_BY       VARCHAR(100)
);

-- BBG_TDC_EXCEPTIONS_VW -------------------------------------------------------
-- EXCEPTION rows for the 'Bloomberg Compare Differences' RULE_CATALOG,
-- plus the four RESULT_DATA-only JSON keys (RULE_NAME, ALADDIN_ID,
-- BBG_VALUE, ALADDIN_VALUE) exposed as their own VARCHAR columns.
-- Overlapping keys (RULE_ID, ID_BB_GLOBAL, ISSUE_DESCRIPTION) are
-- intentionally omitted from the JSON projection so the EXCEPTION-side
-- value wins. The RESULT_DATA column itself is NOT projected — the
-- parsed keys already cover what callers need.
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


-- =============================================================================
-- 3. STORED PROCEDURES (CREATE OR REPLACE)
-- =============================================================================
-- RECON_BBG_COMPARE_VW was retired in favour of the RECON_BBG_COMPARE SP
-- (below). The seed UPDATE on RULE_CATALOG_SOURCE already points at the
-- SP, so the view is no longer referenced anywhere. Section 3 (Views) is
-- intentionally empty.

DROP VIEW IF EXISTS RECON_BBG_COMPARE_VW;

-- RECON_BBG_COMPARE -----------------------------------------------------------
-- Invoked by ExecuteRules via RULE_CATALOG.RULE_CATALOG_SOURCE. When the
-- caller supplies (P_ALADDIN_ID, P_ID_BB_GLOBAL) we reflect that pair per
-- BBG-compare rule. When both are NULL/empty (the "run for all assets"
-- path) we emit a fixed demo set of three assets so the pipeline still
-- produces visible exceptions for testing. RULE_ID is resolved from RULE
-- by RULE_NAME so the Go ExecuteRule layer can tag each emitted exception
-- with its rule (it drops rows that lack RULE_ID).
CREATE OR REPLACE PROCEDURE SP_RECON_BBG_COMPARE(
    P_ALADDIN_ID   VARCHAR,
    P_ID_BB_GLOBAL VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"         VARCHAR,
    "ALADDIN_ID"        VARCHAR,
    "ID_BB_GLOBAL"      VARCHAR,
    "BBG_VALUE"         VARCHAR,
    "ALADDIN_VALUE"     VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RULE_ID"           NUMBER
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH src AS (
            SELECT
                'RULE_DM_BBG_MATURITY_DATE'::VARCHAR AS rule_name,
                '4/18/2029'::VARCHAR                 AS bbg_value,
                '5/15/2029'::VARCHAR                 AS aladdin_value,
                ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
                    '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::VARCHAR
                                                     AS issue_description
            UNION ALL
            SELECT
                'RULE_DM_BBG_REGISTRATION'::VARCHAR,
                'Reg S'::VARCHAR,
                '144A'::VARCHAR,
                ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
                    '144A' || ' BBG Registration:' || 'Reg S')::VARCHAR
        ),
        assets AS (
            SELECT :P_ALADDIN_ID::VARCHAR   AS aladdin_id,
                   :P_ID_BB_GLOBAL::VARCHAR AS id_bb_global
             WHERE :P_ALADDIN_ID IS NOT NULL AND :P_ALADDIN_ID <> ''
            UNION ALL
            SELECT column1::VARCHAR, column2::VARCHAR
            FROM (VALUES
                ('73316NAC9', 'BBG000B7NKY4'),
                ('45661EAB0', 'BBG000B06N81'),
                ('466317AU8', 'BBG016XZK9N4')
            )
            WHERE :P_ALADDIN_ID IS NULL OR :P_ALADDIN_ID = ''
        )
        SELECT src.rule_name         AS "RULE_NAME",
               assets.aladdin_id     AS "ALADDIN_ID",
               assets.id_bb_global   AS "ID_BB_GLOBAL",
               src.bbg_value         AS "BBG_VALUE",
               src.aladdin_value     AS "ALADDIN_VALUE",
               src.issue_description AS "ISSUE_DESCRIPTION",
               r."RULE_ID"           AS "RULE_ID"
        FROM assets
        CROSS JOIN src
        JOIN "RULE" r ON r."RULE_NAME" = src.rule_name
    );
    RETURN TABLE(res);
END;
$$;

-- ARCHIVE_EXCEPTIONS ----------------------------------------------------------
-- Moves the day's EXCEPTION rows for the catalogs implied by (P_RULE_NAME,
-- P_RULE_TYPE) into EXCEPTION_HIST, stamping each with a per-date BATCH_ID
-- (max BATCH_ID for that EXCEPTION_DATE, +1; NULL → 1 for the first run of a
-- new day). Scope rules match GET_RULES — CATALOG/RULE filter by
-- RULE_CATALOG.NAME, GROUP filters by RULE_GROUP.NAME, empty/All matches
-- every catalog. Returns the row count moved.
DROP PROCEDURE IF EXISTS SP_DELETE_EXCEPTIONS(VARCHAR, VARCHAR);

CREATE OR REPLACE PROCEDURE SP_ARCHIVE_EXCEPTIONS(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    exc_date   DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP));
    next_batch NUMBER := 0;
    affected   NUMBER := 0;
BEGIN
    next_batch := COALESCE(
        (SELECT MAX("BATCH_ID") FROM "EXCEPTION_HIST"
          WHERE "EXCEPTION_DATE" = :exc_date), 0
    ) + 1;

    INSERT INTO "EXCEPTION_HIST" (
        "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
        "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "SUPPRESS_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        e."EXCEPTION_ID", e."RULE_ID", e."ASSET_ID", e."EXCEPTION_DATE", :next_batch,
        e."ID_BB_GLOBAL", e."STATE_ID", e."STATUS_ID", e."COMMENTS",
        e."EXCEPTION_TIME", e."ISSUE_DESCRIPTION", e."RESULT_DATA",
        e."SUPPRESS_DATE", e."ASSIGN_TO_ID", e."RESULT_TYPE_ID",
        e."CREATED_DATE", e."CREATED_BY", e."MODIFIED_DATE", e."MODIFIED_BY"
    FROM "EXCEPTION" e
    WHERE e."EXCEPTION_DATE" = :exc_date
      AND e."RULE_ID" IN (
          SELECT r."RULE_ID"
          FROM "RULE" r
          JOIN "RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
          WHERE :P_RULE_NAME IS NULL
             OR :P_RULE_NAME = ''
             OR :P_RULE_NAME = 'All'
             OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                   AND rc."NAME" = :P_RULE_NAME)
             OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                   AND rg."NAME"  = :P_RULE_NAME)
      );
    affected := SQLROWCOUNT;

    DELETE FROM "EXCEPTION"
    WHERE "EXCEPTION_DATE" = :exc_date
      AND "RULE_ID" IN (
          SELECT r."RULE_ID"
          FROM "RULE" r
          JOIN "RULE_CATALOG" rc      ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
          LEFT JOIN "RULE_GROUP" rg   ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
          WHERE :P_RULE_NAME IS NULL
             OR :P_RULE_NAME = ''
             OR :P_RULE_NAME = 'All'
             OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                   AND rc."NAME" = :P_RULE_NAME)
             OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                   AND rg."NAME"  = :P_RULE_NAME)
      );

    RETURN affected;
END;
$$;

-- INHERIT_EXCEPTION_STATUSES --------------------------------------------------
-- For each EXCEPTION row in scope, carry the last-known STATUS_ID from
-- EXCEPTION_HIST forward, keyed by (RULE_ID, ASSET_ID). Row picked by
-- (EXCEPTION_DATE DESC, BATCH_ID DESC) — today's max batch wins when
-- today has archives; else falls back to the most recent prior date's
-- max batch. Scope matches SP_ARCHIVE_EXCEPTIONS / SP_GET_RULES.
CREATE OR REPLACE PROCEDURE SP_INHERIT_EXCEPTION_STATUSES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = h."STATUS_ID",
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
      FROM (
          SELECT "RULE_ID", "ASSET_ID", "STATUS_ID"
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "STATUS_ID",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
                 WHERE "STATUS_ID" IS NOT NULL
            )
           WHERE rn = 1
      ) h
     WHERE e."RULE_ID"  = h."RULE_ID"
       AND e."ASSET_ID" = h."ASSET_ID"
       AND (e."STATUS_ID" IS NULL OR e."STATUS_ID" <> h."STATUS_ID")
       AND e."EXCEPTION_ID" IN (
           SELECT e2."EXCEPTION_ID"
             FROM "EXCEPTION" e2
             JOIN "RULE"          r  ON r."RULE_ID"          = e2."RULE_ID"
             JOIN "RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             LEFT JOIN "RULE_GROUP" rg ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
            WHERE :P_RULE_NAME IS NULL
               OR :P_RULE_NAME = ''
               OR :P_RULE_NAME = 'All'
               OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                     AND rc."NAME" = :P_RULE_NAME)
               OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                     AND rg."NAME"  = :P_RULE_NAME)
       );
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- INSERT_EXCEPTION ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_INSERT_EXCEPTION(
    "RULE_ID"           NUMBER,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATE_ID"         NUMBER,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       VARCHAR,
    "ASSIGN_TO_ID"      NUMBER,
    "RESULT_TYPE_ID"    NUMBER,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR,
    "STATUS_ID"         NUMBER DEFAULT 1
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    -- INSERT ... SELECT (not VALUES) so the COALESCE/NULLIF expression on
    -- STATE_ID is evaluated by the query planner rather than the VALUES
    -- list, which rejects function calls against bound parameters in SF.
    INSERT INTO "EXCEPTION" (
        "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
        "STATE_ID", "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE", "CREATED_BY",
        "STATUS_ID"
    )
    SELECT
        :RULE_ID, :ASSET_ID, :EXCEPTION_DATE, :ID_BB_GLOBAL,
        COALESCE(NULLIF(:STATE_ID, 0), 1),  -- default to Pending
        :EXCEPTION_TIME, :ISSUE_DESCRIPTION, :RESULT_DATA,
        :ASSIGN_TO_ID, :RESULT_TYPE_ID, :CREATED_DATE, :CREATED_BY,
        COALESCE(NULLIF(:STATUS_ID, 0), 1);  -- default to New
    RETURN 'OK';
END;
$$;

-- UPDATE_EXCEPTION ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION(
    P_RULE_ID           NUMBER,
    P_ASSET_ID          VARCHAR,
    P_EXCEPTION_DATE    DATE,
    P_ID_BB_GLOBAL      VARCHAR,
    P_STATE_ID         NUMBER,
    P_EXCEPTION_TIME    TIMESTAMP_NTZ,
    P_ISSUE_DESCRIPTION VARCHAR,
    P_RESULT_DATA       VARCHAR,
    P_ASSIGN_TO_ID      NUMBER,
    P_RESULT_TYPE_ID    NUMBER,
    P_CREATED_DATE      TIMESTAMP_NTZ,
    P_CREATED_BY        VARCHAR,
    P_STATUS_ID         NUMBER DEFAULT NULL
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    UPDATE "EXCEPTION"
       SET "EXCEPTION_DATE"    = :P_EXCEPTION_DATE,
           "EXCEPTION_TIME"    = :P_EXCEPTION_TIME,
           "STATE_ID"         = 1,  -- re-flagged -> Pending
           "ISSUE_DESCRIPTION" = :P_ISSUE_DESCRIPTION,
           "RESULT_DATA"       = COALESCE(:P_RESULT_DATA, "RESULT_DATA"),
           "ASSIGN_TO_ID"      = COALESCE(:P_ASSIGN_TO_ID, "ASSIGN_TO_ID"),
           "RESULT_TYPE_ID"    = :P_RESULT_TYPE_ID,
           "CREATED_DATE"      = :P_CREATED_DATE,
           "CREATED_BY"        = :P_CREATED_BY,
           "ID_BB_GLOBAL"      = COALESCE(:P_ID_BB_GLOBAL, "ID_BB_GLOBAL"),
           "STATUS_ID"         = COALESCE(:P_STATUS_ID, "STATUS_ID")
     WHERE "ASSET_ID" = :P_ASSET_ID
       AND "RULE_ID"  = :P_RULE_ID;
    RETURN 'OK';
END;
$$;

-- UPDATE_EXCEPTION_STATE -----------------------------------------------------
-- Bumps MODIFIED_DATE / MODIFIED_BY on every matching row. Flips STATE_ID
-- to 4 (Complete) only when P_COMPLETE is true.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_STATE(
    P_ASSET_ID VARCHAR,
    P_RULE_ID  NUMBER,
    P_COMPLETE BOOLEAN DEFAULT FALSE
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "STATE_ID"     = CASE WHEN :P_COMPLETE THEN 4 ELSE "STATE_ID" END,
           "MODIFIED_DATE" = CURRENT_TIMESTAMP::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "ASSET_ID"      = :P_ASSET_ID
       AND "RULE_ID"       = :P_RULE_ID;
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_EXCEPTION_STATUS -----------------------------------------------------
-- Sets EXCEPTION.STATUS_ID for the row identified by P_EXCEPTION_ID,
-- resolving P_STATUS_NAME against EXCEPTION_STATUS.NAME. Returns row count.
-- Side effect for 'Accept': the row is snapshotted into EXCEPTION_OVERRIDE.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_STATUS(
    P_EXCEPTION_ID NUMBER,
    P_STATUS_NAME  VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = (
               SELECT "EXCEPTION_STATUS_ID"
               FROM "EXCEPTION_STATUS"
               WHERE "NAME" = :P_STATUS_NAME
               LIMIT 1
           ),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID
       AND EXISTS (
           SELECT 1 FROM "EXCEPTION_STATUS" WHERE "NAME" = :P_STATUS_NAME
       )
       AND NOT (:P_STATUS_NAME = 'Suppress' AND "SUPPRESS_DATE" IS NULL);
    affected := SQLROWCOUNT;

    IF (:P_STATUS_NAME = 'Accept' AND affected > 0) THEN
        INSERT INTO "EXCEPTION_OVERRIDE" (
            "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
            "STATE_ID", "STATUS_ID", "COMMENTS", "EXCEPTION_TIME",
            "ISSUE_DESCRIPTION", "RESULT_DATA", "SUPPRESS_DATE",
            "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE",
            "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        )
        SELECT
            "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
            "STATE_ID", "STATUS_ID", "COMMENTS", "EXCEPTION_TIME",
            "ISSUE_DESCRIPTION", "RESULT_DATA", "SUPPRESS_DATE",
            "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE",
            "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
        FROM "EXCEPTION"
        WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;
    END IF;

    RETURN affected;
END;
$$;

-- UPDATE_EXCEPTION_COMMENTS ---------------------------------------------------
-- Sets EXCEPTION.COMMENTS for the row identified by P_EXCEPTION_ID.
-- Returns 1 on success, 0 if the row did not match.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_COMMENTS(
    P_EXCEPTION_ID NUMBER,
    P_COMMENTS     VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "COMMENTS"      = :P_COMMENTS,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_EXCEPTION_SUPPRESS_DATE ----------------------------------------------
-- Sets EXCEPTION.SUPPRESS_DATE for the row identified by P_EXCEPTION_ID.
-- NULL P_SUPPRESS_DATE clears the cell. Returns 1 on success.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_SUPPRESS_DATE(
    P_EXCEPTION_ID  NUMBER,
    P_SUPPRESS_DATE DATE
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "SUPPRESS_DATE" = :P_SUPPRESS_DATE,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- EXPIRE_SUPPRESS_DATES -------------------------------------------------------
-- Reverts every EXCEPTION row whose SUPPRESS_DATE has passed (< today UTC)
-- back to STATUS_ID=1 ("New") and clears SUPPRESS_DATE. Called at the top
-- of GetExceptions in Go so the grid never shows a stale Suppress row.
CREATE OR REPLACE PROCEDURE SP_EXPIRE_SUPPRESS_DATES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = 1,
           "SUPPRESS_DATE" = NULL,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "SUPPRESS_DATE" IS NOT NULL
       AND "SUPPRESS_DATE" < TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP));
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_EXCEPTION_ASSIGN_TO --------------------------------------------------
-- Single-row variant. Sets EXCEPTION.ASSIGN_TO_ID on the row identified
-- by P_EXCEPTION_ID, resolving P_ASSIGN_TO against DM_USER.USER.
-- Empty/NULL clears the assignment. Distinct from SP_UPDATE_ASSIGN_TO
-- which mutates every EXCEPTION row for an ASSET_ID.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_ASSIGN_TO(
    P_EXCEPTION_ID NUMBER,
    P_ASSIGN_TO    VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
    user_id  NUMBER := NULL;
BEGIN
    IF (:P_ASSIGN_TO IS NOT NULL AND :P_ASSIGN_TO <> '') THEN
        SELECT "ID" INTO :user_id
        FROM "DM_USER"
        WHERE "USER" = :P_ASSIGN_TO
        LIMIT 1;
    END IF;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_ASSIGN_TO ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_UPDATE_ASSIGN_TO(
    P_ASSET_ID  VARCHAR,
    P_ASSIGN_TO VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
    user_id  NUMBER := NULL;
BEGIN
    IF (:P_ASSIGN_TO IS NOT NULL AND :P_ASSIGN_TO <> '') THEN
        SELECT "ID" INTO :user_id
        FROM "DM_USER"
        WHERE "USER" = :P_ASSIGN_TO
        LIMIT 1;
    END IF;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = CURRENT_TIMESTAMP::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "ASSET_ID" = :P_ASSET_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- GET_DM_USERS ----------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_DM_USERS()
RETURNS TABLE("USER" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "USER"
        FROM "DM_USER"
        ORDER BY "ID" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_RULE_GROUPS -------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_RULE_GROUPS()
RETURNS TABLE("NAME" VARCHAR, "FLAG_STATUS_VISIBLE" BOOLEAN, "FLAG_COMMENTS_VISIBLE" BOOLEAN, "FLAG_SUPPRESS_DATE" BOOLEAN, "FLAG_ASSIGN_TO_VISIBLE" BOOLEAN)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME",
               COALESCE("FLAG_STATUS_VISIBLE",    FALSE) AS "FLAG_STATUS_VISIBLE",
               COALESCE("FLAG_COMMENTS_VISIBLE",  FALSE) AS "FLAG_COMMENTS_VISIBLE",
               COALESCE("FLAG_SUPPRESS_DATE",     FALSE) AS "FLAG_SUPPRESS_DATE",
               COALESCE("FLAG_ASSIGN_TO_VISIBLE", FALSE) AS "FLAG_ASSIGN_TO_VISIBLE"
        FROM "RULE_GROUP"
        ORDER BY "RULE_GROUP_ID" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_RULE_CATALOGS -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_RULE_CATALOGS(
    P_RULE_GROUP VARCHAR
)
RETURNS TABLE("RULE_CATALOG_NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT rc."NAME" AS "RULE_CATALOG_NAME"
        FROM "RULE_CATALOG" rc
        JOIN "RULE_GROUP" rg
          ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
        WHERE rg."NAME" = :P_RULE_GROUP
        ORDER BY rc."RULE_CATALOG_ID" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_RULE_NAMES --------------------------------------------------------------
-- Returns individual RULE_NAMEs (and their RULE_DESCRIPTION) belonging to a
-- given catalog. Used by the tcw-dqm tree view to display the friendlier
-- description on the leaf when present (fall back to RULE_NAME) and to
-- populate the Exceptions header subtitle when a specific rule is selected.
CREATE OR REPLACE PROCEDURE SP_GET_RULE_NAMES(
    P_RULE_CATALOG VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"        VARCHAR,
    "RULE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT r."RULE_NAME"        AS "RULE_NAME",
               r."RULE_DESCRIPTION" AS "RULE_DESCRIPTION"
        FROM "RULE" r
        JOIN "RULE_CATALOG" rc
          ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
        WHERE rc."NAME" = :P_RULE_CATALOG
        ORDER BY r."RULE_NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_RULES -------------------------------------------------------------------
-- One row per RULE_CATALOG. RULE_COMMAND is RULE_CATALOG_SOURCE (the SQL
-- the Go ExecuteRule layer runs; the result set must include a RULE_ID
-- column per row). ENVIRONMENT is RULE_CATALOG_CONNECTION.
--
-- Filtering:
--   P_RULE_TYPE = 'CATALOG' or 'RULE' (RULE behaves the same as CATALOG
--     for now) â†’ P_RULE_NAME matches RULE_CATALOG.NAME.
--   P_RULE_TYPE = 'GROUP'  â†’ P_RULE_NAME matches RULE_GROUP.NAME; returns
--     every catalog whose RULE_GROUP_ID resolves to that group.
--   P_RULE_NAME NULL / empty / 'All' â†’ no filter, return every catalog.
CREATE OR REPLACE PROCEDURE SP_GET_RULES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"   NUMBER,
    "RULE_CATALOG_NAME" VARCHAR,
    "RULE_COMMAND"      VARCHAR,
    "ENVIRONMENT"       VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT rc."RULE_CATALOG_ID"         AS "RULE_CATALOG_ID",
               rc."NAME"                    AS "RULE_CATALOG_NAME",
               rc."RULE_CATALOG_SOURCE"     AS "RULE_COMMAND",
               rc."RULE_CATALOG_CONNECTION" AS "ENVIRONMENT"
        FROM "RULE_CATALOG" rc
        LEFT JOIN "RULE_GROUP" rg
          ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
        WHERE :P_RULE_NAME IS NULL
           OR :P_RULE_NAME = ''
           OR :P_RULE_NAME = 'All'
           OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) IN ('CATALOG','RULE')
                 AND rc."NAME" = :P_RULE_NAME)
           OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                 AND rg."NAME"  = :P_RULE_NAME)
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTION_STATE --------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_STATE()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "EXCEPTION_STATE"
        ORDER BY "SORT_ORDER" ASC, "NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTION_STATUS -------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_STATUS()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "EXCEPTION_STATUS"
        ORDER BY "SORT_ORDER" ASC, "NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTION_TYPE ----------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_TYPE()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "EXCEPTION_TYPE"
        ORDER BY "SORT_ORDER" ASC, "NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_PRIORITY_TYPE -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_PRIORITY_TYPE()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "EXCEPTION_PRIORITY_TYPE"
        ORDER BY "SORT_ORDER" ASC, "NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_SEVERITY_TYPE -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_SEVERITY_TYPE()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "EXCEPTION_SEVERITY_TYPE"
        ORDER BY "SORT_ORDER" ASC, "NAME" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTIONS --------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTIONS(
    P_ASSET_ID          VARCHAR DEFAULT NULL,
    P_EXCEPTION_TYPE    VARCHAR DEFAULT NULL,
    P_SEVERITY          VARCHAR DEFAULT NULL,
    P_PRIORITY          VARCHAR DEFAULT NULL,
    P_RULE_CATALOG      VARCHAR DEFAULT NULL,
    P_RULE_NAME         VARCHAR DEFAULT NULL,
    P_RULE_GROUP        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE  VARCHAR DEFAULT NULL,
    P_ASSIGN_TO         VARCHAR DEFAULT NULL,
    P_RULE_NAME_PATTERN VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "EXCEPTION_ID"      NUMBER,
    "RULE_ID"           NUMBER,
    "RULE_NAME"         VARCHAR,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATE_ID"         NUMBER,
    "EXCEPTION_STATE"  VARCHAR,
    "STATUS_ID"        NUMBER,
    "EXCEPTION_STATUS" VARCHAR,
    "COMMENTS"          VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       VARCHAR,
    "SUPPRESS_DATE"     DATE,
    "ASSIGN_TO_ID"      NUMBER,
    "ASSIGN_TO"         VARCHAR,
    "RESULT_TYPE_ID"    NUMBER,
    "PRIORITY"          VARCHAR,
    "SEVERITY"          VARCHAR,
    "EXCEPTION_TYPE"    VARCHAR,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR,
    "MODIFIED_DATE"     TIMESTAMP_NTZ,
    "MODIFIED_BY"       VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT e."EXCEPTION_ID"            AS "EXCEPTION_ID",
               e."RULE_ID"                 AS "RULE_ID",
               r."RULE_NAME"               AS "RULE_NAME",
               e."ASSET_ID"                AS "ASSET_ID",
               e."EXCEPTION_DATE"          AS "EXCEPTION_DATE",
               e."EXCEPTION_TIME"          AS "EXCEPTION_TIME",
               e."ID_BB_GLOBAL"            AS "ID_BB_GLOBAL",
               e."STATE_ID"               AS "STATE_ID",
               es."NAME"                   AS "EXCEPTION_STATE",
               e."STATUS_ID"               AS "STATUS_ID",
               est_s."NAME"                AS "EXCEPTION_STATUS",
               e."COMMENTS"                AS "COMMENTS",
               e."ISSUE_DESCRIPTION"       AS "ISSUE_DESCRIPTION",
               TO_VARCHAR(e."RESULT_DATA") AS "RESULT_DATA",
               e."SUPPRESS_DATE"           AS "SUPPRESS_DATE",
               e."ASSIGN_TO_ID"            AS "ASSIGN_TO_ID",
               du."USER"                   AS "ASSIGN_TO",
               e."RESULT_TYPE_ID"          AS "RESULT_TYPE_ID",
               ept."NAME"                  AS "PRIORITY",
               est."NAME"                  AS "SEVERITY",
               et."NAME"                   AS "EXCEPTION_TYPE",
               e."CREATED_DATE"            AS "CREATED_DATE",
               e."CREATED_BY"              AS "CREATED_BY",
               e."MODIFIED_DATE"           AS "MODIFIED_DATE",
               e."MODIFIED_BY"             AS "MODIFIED_BY"
        FROM "EXCEPTION" e
        LEFT JOIN "RULE"                   r   ON r."RULE_ID"                     = e."RULE_ID"
        LEFT JOIN "EXCEPTION_TYPE"          et  ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
        LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
        LEFT JOIN "RULE_CATALOG"            rc  ON rc."RULE_CATALOG_ID"             = r."RULE_CATALOG_ID"
        LEFT JOIN "RULE_GROUP"              rg  ON rg."RULE_GROUP_ID"               = rc."RULE_GROUP_ID"
        LEFT JOIN "EXCEPTION_STATE"        es    ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
        LEFT JOIN "EXCEPTION_STATUS"       est_s ON est_s."EXCEPTION_STATUS_ID"      = e."STATUS_ID"
        LEFT JOIN "DM_USER"                 du    ON du."ID"                          = e."ASSIGN_TO_ID"
        WHERE (:P_ASSET_ID          IS NULL OR e."ASSET_ID" = :P_ASSET_ID)
          AND (:P_EXCEPTION_TYPE    IS NULL OR et."NAME"    = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY          IS NULL OR est."NAME"   = :P_SEVERITY)
          AND (:P_PRIORITY          IS NULL OR ept."NAME"   = :P_PRIORITY)
          AND (:P_RULE_CATALOG      IS NULL OR :P_RULE_CATALOG  = 'All' OR rc."NAME" = :P_RULE_CATALOG)
          AND (:P_RULE_NAME         IS NULL OR :P_RULE_NAME  = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_RULE_GROUP        IS NULL OR :P_RULE_GROUP = 'All' OR rg."NAME" = :P_RULE_GROUP)
          AND (:P_EXCEPTION_STATE  IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME" = :P_EXCEPTION_STATE)
          AND (:P_ASSIGN_TO         IS NULL OR :P_ASSIGN_TO = 'All' OR du."USER" = :P_ASSIGN_TO)
          AND (:P_RULE_NAME_PATTERN IS NULL OR r."RULE_NAME" ILIKE :P_RULE_NAME_PATTERN)
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTION_HIST_DATES ---------------------------------------------------
-- Distinct EXCEPTION_DATEs from EXCEPTION_HIST within the last 60 days
-- (UTC), most recent first. Powers the "DQM Date" dropdown.
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_HIST_DATES()
RETURNS TABLE("EXCEPTION_DATE" DATE)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT DISTINCT "EXCEPTION_DATE"
          FROM "EXCEPTION_HIST"
         WHERE "EXCEPTION_DATE" IS NOT NULL
           AND "EXCEPTION_DATE" >= DATEADD(day, -60, TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP)))
         ORDER BY "EXCEPTION_DATE" DESC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_EXCEPTIONS_HIST --------------------------------------------------------
-- Same column shape as SP_GET_EXCEPTIONS. Reads EXCEPTION_HIST for the
-- given P_EXCEPTION_DATE and only the LATEST BATCH_ID within the caller's
-- rule/catalog/group scope, so the grid shows the last archived snapshot
-- for that day.
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTIONS_HIST(
    P_EXCEPTION_DATE    DATE,
    P_ASSET_ID          VARCHAR DEFAULT NULL,
    P_EXCEPTION_TYPE    VARCHAR DEFAULT NULL,
    P_SEVERITY          VARCHAR DEFAULT NULL,
    P_PRIORITY          VARCHAR DEFAULT NULL,
    P_RULE_CATALOG      VARCHAR DEFAULT NULL,
    P_RULE_NAME         VARCHAR DEFAULT NULL,
    P_RULE_GROUP        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE   VARCHAR DEFAULT NULL,
    P_ASSIGN_TO         VARCHAR DEFAULT NULL,
    P_RULE_NAME_PATTERN VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "EXCEPTION_ID"      NUMBER,
    "RULE_ID"           NUMBER,
    "RULE_NAME"         VARCHAR,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATE_ID"          NUMBER,
    "EXCEPTION_STATE"   VARCHAR,
    "STATUS_ID"         NUMBER,
    "EXCEPTION_STATUS"  VARCHAR,
    "COMMENTS"          VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       VARCHAR,
    "SUPPRESS_DATE"     DATE,
    "ASSIGN_TO_ID"      NUMBER,
    "ASSIGN_TO"         VARCHAR,
    "RESULT_TYPE_ID"    NUMBER,
    "PRIORITY"          VARCHAR,
    "SEVERITY"          VARCHAR,
    "EXCEPTION_TYPE"    VARCHAR,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR,
    "MODIFIED_DATE"     TIMESTAMP_NTZ,
    "MODIFIED_BY"       VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH max_batch AS (
            SELECT MAX(h."BATCH_ID") AS mb
              FROM "EXCEPTION_HIST" h
              LEFT JOIN "RULE"         r  ON r."RULE_ID"          = h."RULE_ID"
              LEFT JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
              LEFT JOIN "RULE_GROUP"   rg ON rg."RULE_GROUP_ID"   = rc."RULE_GROUP_ID"
             WHERE h."EXCEPTION_DATE" = :P_EXCEPTION_DATE
               AND (:P_RULE_CATALOG IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME" = :P_RULE_CATALOG)
               AND (:P_RULE_NAME    IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
               AND (:P_RULE_GROUP   IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
        )
        SELECT e."EXCEPTION_ID"            AS "EXCEPTION_ID",
               e."RULE_ID"                 AS "RULE_ID",
               r."RULE_NAME"               AS "RULE_NAME",
               e."ASSET_ID"                AS "ASSET_ID",
               e."EXCEPTION_DATE"          AS "EXCEPTION_DATE",
               e."EXCEPTION_TIME"          AS "EXCEPTION_TIME",
               e."ID_BB_GLOBAL"            AS "ID_BB_GLOBAL",
               e."STATE_ID"                AS "STATE_ID",
               es."NAME"                   AS "EXCEPTION_STATE",
               e."STATUS_ID"               AS "STATUS_ID",
               est_s."NAME"                AS "EXCEPTION_STATUS",
               e."COMMENTS"                AS "COMMENTS",
               e."ISSUE_DESCRIPTION"       AS "ISSUE_DESCRIPTION",
               TO_VARCHAR(e."RESULT_DATA") AS "RESULT_DATA",
               e."SUPPRESS_DATE"           AS "SUPPRESS_DATE",
               e."ASSIGN_TO_ID"            AS "ASSIGN_TO_ID",
               du."USER"                   AS "ASSIGN_TO",
               e."RESULT_TYPE_ID"          AS "RESULT_TYPE_ID",
               ept."NAME"                  AS "PRIORITY",
               est."NAME"                  AS "SEVERITY",
               et."NAME"                   AS "EXCEPTION_TYPE",
               e."CREATED_DATE"            AS "CREATED_DATE",
               e."CREATED_BY"              AS "CREATED_BY",
               e."MODIFIED_DATE"           AS "MODIFIED_DATE",
               e."MODIFIED_BY"             AS "MODIFIED_BY"
        FROM "EXCEPTION_HIST" e
        LEFT JOIN "RULE"                    r     ON r."RULE_ID"                     = e."RULE_ID"
        LEFT JOIN "EXCEPTION_TYPE"          et    ON et."EXCEPTION_TYPE_ID"          = r."EXCEPTION_TYPE_ID"
        LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept   ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
        LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est   ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
        LEFT JOIN "RULE_CATALOG"            rc    ON rc."RULE_CATALOG_ID"            = r."RULE_CATALOG_ID"
        LEFT JOIN "RULE_GROUP"              rg    ON rg."RULE_GROUP_ID"              = rc."RULE_GROUP_ID"
        LEFT JOIN "EXCEPTION_STATE"         es    ON es."EXCEPTION_STATE_ID"         = e."STATE_ID"
        LEFT JOIN "EXCEPTION_STATUS"        est_s ON est_s."EXCEPTION_STATUS_ID"     = e."STATUS_ID"
        LEFT JOIN "DM_USER"                 du    ON du."ID"                         = e."ASSIGN_TO_ID"
        WHERE e."EXCEPTION_DATE" = :P_EXCEPTION_DATE
          AND e."BATCH_ID" = (SELECT mb FROM max_batch)
          AND (:P_ASSET_ID          IS NULL OR e."ASSET_ID" = :P_ASSET_ID)
          AND (:P_EXCEPTION_TYPE    IS NULL OR et."NAME"    = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY          IS NULL OR est."NAME"   = :P_SEVERITY)
          AND (:P_PRIORITY          IS NULL OR ept."NAME"   = :P_PRIORITY)
          AND (:P_RULE_CATALOG      IS NULL OR :P_RULE_CATALOG = 'All' OR rc."NAME" = :P_RULE_CATALOG)
          AND (:P_RULE_NAME         IS NULL OR :P_RULE_NAME    = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_RULE_GROUP        IS NULL OR :P_RULE_GROUP   = 'All' OR rg."NAME"     = :P_RULE_GROUP)
          AND (:P_EXCEPTION_STATE   IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME" = :P_EXCEPTION_STATE)
          AND (:P_ASSIGN_TO         IS NULL OR :P_ASSIGN_TO = 'All' OR du."USER" = :P_ASSIGN_TO)
          AND (:P_RULE_NAME_PATTERN IS NULL OR r."RULE_NAME" ILIKE :P_RULE_NAME_PATTERN)
    );
    RETURN TABLE(res);
END;
$$;

-- GET_ASSETS ------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SP_GET_ASSETS(
    P_EXCEPTION_TYPE   VARCHAR DEFAULT NULL,
    P_SEVERITY         VARCHAR DEFAULT NULL,
    P_PRIORITY         VARCHAR DEFAULT NULL,
    P_RULE_CATALOG     VARCHAR DEFAULT NULL,
    P_RULE_NAME        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATE VARCHAR DEFAULT NULL,
    P_ASSIGN_TO        VARCHAR DEFAULT NULL,
    P_RULE_GROUP       VARCHAR DEFAULT NULL
)
RETURNS TABLE (
    "EXCEPTION_DATE"       TIMESTAMP_NTZ,
    "PRIORITY"             VARCHAR,
    "SEVERITY"             VARCHAR,
    "TYPE"                 VARCHAR,
    "ASSIGN_TO"            VARCHAR,
    "ASSET_ID"             VARCHAR,
    "FIGI"                 VARCHAR,
    "SECURITY_DESCRIPTION" VARCHAR,
    "TRADER"               VARCHAR,
    "TRADING_TEAM"         VARCHAR,
    "EXCEPTION_COUNT"      NUMBER,
    "BBG_LAST_REFRESH"     VARCHAR,
    "ALL_COMPLETE"         BOOLEAN
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        WITH filtered AS (
            SELECT
                e."ASSET_ID",
                e."EXCEPTION_TIME",
                e."ID_BB_GLOBAL",
                ept."NAME"       AS priority_name,
                ept."SORT_ORDER" AS priority_rank,
                est."NAME"       AS severity_name,
                est."SORT_ORDER" AS severity_rank,
                et."NAME"        AS type_name,
                et."SORT_ORDER"  AS type_rank,
                es."NAME"        AS state_name,
                du."USER"        AS assign_to_user
            FROM "EXCEPTION" e
            JOIN "RULE" r
              ON r."RULE_ID" = e."RULE_ID"
            LEFT JOIN "EXCEPTION_PRIORITY_TYPE" ept
              ON ept."EXCEPTION_PRIORITY_TYPE_ID" = r."EXCEPTION_PRIORITY_TYPE_ID"
            LEFT JOIN "EXCEPTION_SEVERITY_TYPE" est
              ON est."EXCEPTION_SEVERITY_TYPE_ID" = r."EXCEPTION_SEVERITY_TYPE_ID"
            LEFT JOIN "EXCEPTION_TYPE" et
              ON et."EXCEPTION_TYPE_ID" = r."EXCEPTION_TYPE_ID"
            LEFT JOIN "RULE_CATALOG" rc
              ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            LEFT JOIN "RULE_GROUP" rg
              ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
            LEFT JOIN "EXCEPTION_STATE" es
              ON es."EXCEPTION_STATE_ID" = e."STATE_ID"
            LEFT JOIN "DM_USER" du
              ON du."ID" = e."ASSIGN_TO_ID"
            WHERE (:P_EXCEPTION_TYPE   IS NULL OR et."NAME"  = :P_EXCEPTION_TYPE)
              AND (:P_SEVERITY         IS NULL OR est."NAME" = :P_SEVERITY)
              AND (:P_PRIORITY         IS NULL OR ept."NAME" = :P_PRIORITY)
              AND (:P_RULE_GROUP       IS NULL OR :P_RULE_GROUP       = 'All' OR rg."NAME"      = :P_RULE_GROUP)
              AND (:P_RULE_CATALOG     IS NULL OR :P_RULE_CATALOG     = 'All' OR rc."NAME"      = :P_RULE_CATALOG)
              AND (:P_RULE_NAME        IS NULL OR :P_RULE_NAME        = 'All' OR r."RULE_NAME"  = :P_RULE_NAME)
              AND (:P_EXCEPTION_STATE IS NULL OR :P_EXCEPTION_STATE = 'All' OR es."NAME"      = :P_EXCEPTION_STATE)
              AND (:P_ASSIGN_TO        IS NULL OR :P_ASSIGN_TO        = 'All' OR du."USER"      = :P_ASSIGN_TO)
        )
        SELECT
            MAX("EXCEPTION_TIME")                                  AS "EXCEPTION_DATE",
            MIN_BY(priority_name, priority_rank)                   AS "PRIORITY",
            MIN_BY(severity_name, severity_rank)                   AS "SEVERITY",
            MIN_BY(type_name, type_rank)                           AS "TYPE",
            MAX_BY(assign_to_user, "EXCEPTION_TIME")               AS "ASSIGN_TO",
            "ASSET_ID"                                             AS "ASSET_ID",
            MAX_BY("ID_BB_GLOBAL", "EXCEPTION_TIME")               AS "FIGI",
            'XYZ'                                                  AS "SECURITY_DESCRIPTION",
            'Colman Slain'                                         AS "TRADER",
            'ABS'                                                  AS "TRADING_TEAM",
            COUNT_IF(COALESCE(state_name, '') <> 'Complete')      AS "EXCEPTION_COUNT",
            '10:55 AM'                                             AS "BBG_LAST_REFRESH",
            -- ALL_COMPLETE: asset-level property, true iff every EXCEPTION row
            -- for the asset (across all statuses, ignoring user filters) has
            -- status 'Complete'. Computed via a correlated subquery against
            -- the unfiltered EXCEPTION table.
            (SELECT COUNT(*) > 0
                    AND COUNT_IF(COALESCE(es_all."NAME", '') <> 'Complete') = 0
               FROM "EXCEPTION" e_all
               LEFT JOIN "EXCEPTION_STATE" es_all
                 ON es_all."EXCEPTION_STATE_ID" = e_all."STATE_ID"
              WHERE e_all."ASSET_ID" = filtered."ASSET_ID")        AS "ALL_COMPLETE"
        FROM filtered
        GROUP BY "ASSET_ID"
        ORDER BY "ASSET_ID"
    );
    RETURN TABLE(res);
END;
$$;

-- INSERT_SECURITY_EXCEPTION ---------------------------------------------------
-- Legacy procedure kept for ad-hoc backfills against the SECURITY_EXCEPTION
-- table (not created here; managed externally). No active Go caller.
CREATE OR REPLACE PROCEDURE SP_INSERT_SECURITY_EXCEPTION(
    "RULE_ID"               NUMBER,
    "RUN_DATE"              TIMESTAMP_NTZ,
    "RUN_START"             TIMESTAMP_NTZ,
    "RUN_END"               TIMESTAMP_NTZ,
    "RESULT_TYPE_ID"        NUMBER,
    "EXCEPTION_STATUS_ID"   NUMBER,
    "SEVERITY_TYPE_ID"      NUMBER,
    "PROCESS_TYPE_ID"       NUMBER,
    "CATEGORY_TYPE_ID"      NUMBER,
    "ASSIGN_TO_ID"          NUMBER,
    "ASSIGN_TO_DATE"        VARCHAR,
    "RESOLVE_DATE"          VARCHAR,
    "BUS_TERM_SOURCE_ID"    NUMBER,
    "ISSUE_DESCRIPTION"     VARCHAR,
    "SOURCE_SYSTEM_CODE"    VARCHAR,
    "CREATED_DATE"          TIMESTAMP_NTZ,
    "CREATED_BY"            VARCHAR,
    "MODIFIED_BY"           VARCHAR,
    "MODIFIED_DATE"         TIMESTAMP_NTZ,
    "EXCEPTION_SOURCE_ID"   NUMBER,
    "EXCEPTION_TYPE_ID"     NUMBER,
    "DQM_APP_ID"            NUMBER,
    "ASSET_TYPE_ID"         NUMBER,
    "ASSET"                 VARCHAR,
    "CUSIP_TYPE_CODE"       VARCHAR,
    "ASSIGNED_BY"           VARCHAR,
    "COMMENTS"              VARCHAR,
    "ASSET_ID"              VARCHAR,
    "ID_BB_GLOBAL"          VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO "SECURITY_EXCEPTION" (
        "RULE_ID", "RUN_DATE", "RUN_START", "RUN_END",
        "RESULT_TYPE_ID", "EXCEPTION_STATUS_ID", "SEVERITY_TYPE_ID", "PROCESS_TYPE_ID",
        "CATEGORY_TYPE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_DATE", "RESOLVE_DATE",
        "BUS_TERM_SOURCE_ID", "ISSUE_DESCRIPTION", "SOURCE_SYSTEM_CODE",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_BY", "MODIFIED_DATE",
        "EXCEPTION_SOURCE_ID", "EXCEPTION_TYPE_ID", "DQM_APP_ID", "ASSET_TYPE_ID",
        "ASSET", "CUSIP_TYPE_CODE", "ASSIGNED_BY", "COMMENTS", "ASSET_ID",
        "ID_BB_GLOBAL"
    ) VALUES (
        :RULE_ID, :RUN_DATE, :RUN_START, :RUN_END,
        :RESULT_TYPE_ID,
        COALESCE(NULLIF(:EXCEPTION_STATUS_ID, 0), 1),  -- default to Pending
        :SEVERITY_TYPE_ID, :PROCESS_TYPE_ID,
        :CATEGORY_TYPE_ID, :ASSIGN_TO_ID, :ASSIGN_TO_DATE, :RESOLVE_DATE,
        :BUS_TERM_SOURCE_ID, :ISSUE_DESCRIPTION, :SOURCE_SYSTEM_CODE,
        :CREATED_DATE, :CREATED_BY, :MODIFIED_BY, :MODIFIED_DATE,
        :EXCEPTION_SOURCE_ID, :EXCEPTION_TYPE_ID, :DQM_APP_ID, :ASSET_TYPE_ID,
        :ASSET, :CUSIP_TYPE_CODE, :ASSIGNED_BY, :COMMENTS, :ASSET_ID,
        :ID_BB_GLOBAL
    );
    RETURN 'OK';
END;
$$;


-- =============================================================================
-- 5. MIGRATION SCRIPTS (one-time â€” DO NOT include in repeated rerun)
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

-- End of snowflake_dq.sql
