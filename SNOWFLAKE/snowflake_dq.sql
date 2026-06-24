-- =============================================================================
-- snowflake_dq.sql
--
-- Combined Snowflake setup for the security-rules / DQM application.
-- Database: TCW_CORE_DEV, Schema: DATA_QUALITY.
-- This is the canonical "fresh environment" script — running it brings the
-- DATA_QUALITY schema to the objects + seed data the Go service expects.
--
-- RERUNNABILITY:
--   * Every object uses CREATE OR REPLACE — tables, views, procedures.
--   * Lookup AND operational tables (DM_USER, RULE_GROUP, RULE_CATALOG, RULE,
--     EXCEPTION, EXCEPTION_HIST, EXCEPTION_STATUS, EXCEPTION_TYPE,
--     EXCEPTION_PRIORITY_TYPE, EXCEPTION_SEVERITY_TYPE) are dropped and
--     recreated on each run, then re-seeded from the literal VALUES in
--     this script. Running this file destroys existing row data in those
--     tables — that is the intended semantic for repeatable environment
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

-- EXCEPTION_STATUS ------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_STATUS (
    EXCEPTION_STATUS_ID INT,
    NAME                VARCHAR(100),
    SORT_ORDER          INT,
    CREATED_BY          VARCHAR(100),
    CREATED_DATE        TIMESTAMP_NTZ(9)
);

INSERT INTO EXCEPTION_STATUS (EXCEPTION_STATUS_ID, NAME, SORT_ORDER, CREATED_BY, CREATED_DATE) VALUES
    (1, 'Pending',  10, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (5, 'OnHold',   15, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (2, 'Assigned', 20, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (3, 'WorkedOn', 30, CURRENT_USER(), CURRENT_TIMESTAMP()),
    (4, 'Complete', 40, CURRENT_USER(), CURRENT_TIMESTAMP());

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
-- 2. OPERATIONAL DATA TABLES (CREATE OR REPLACE — resets data on rerun)
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
    RULE_GROUP_ID NUMBER(38,0) IDENTITY(1,1) PRIMARY KEY,
    NAME          VARCHAR(100),
    DESCRIPTION   VARCHAR(512),
    CREATED_DATE  TIMESTAMP_NTZ(9),
    CREATED_BY    VARCHAR(100)
);

INSERT INTO RULE_GROUP (NAME, DESCRIPTION, CREATED_DATE, CREATED_BY) VALUES
    ('Security Master', 'Security Master', CURRENT_TIMESTAMP(), CURRENT_USER());

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
    'CALL RECON_BBG_COMPARE(${ASSET_ID}, ${ID_BB_GLOBAL})',
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
    STATUS_ID         INT,
    COMMENT_ID        INT,
    EXCEPTION_TIME    TIMESTAMP_NTZ(9),
    ISSUE_DESCRIPTION VARCHAR(512),
    RESULT_DATA       OBJECT,
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
    ID_BB_GLOBAL      VARCHAR(15),
    STATUS_ID         INT,
    COMMENT_ID        INT,
    EXCEPTION_TIME    TIMESTAMP_NTZ(9),
    ISSUE_DESCRIPTION VARCHAR(512),
    RESULT_DATA       OBJECT,
    SUPPRESS_DATE     DATE,
    ASSIGN_TO_ID      INT,
    RESULT_TYPE_ID    INT,
    CREATED_DATE      TIMESTAMP_NTZ(9),
    CREATED_BY        VARCHAR(100),
    MODIFIED_DATE     TIMESTAMP_NTZ(9),
    MODIFIED_BY       VARCHAR(100)
);


-- =============================================================================
-- 3. STORED PROCEDURES (CREATE OR REPLACE)
-- =============================================================================
-- RECON_BBG_COMPARE_VW was retired in favour of the RECON_BBG_COMPARE SP
-- (below). The seed UPDATE on RULE_CATALOG_SOURCE already points at the
-- SP, so the view is no longer referenced anywhere. Section 3 (Views) is
-- intentionally empty.

DROP VIEW IF EXISTS RECON_BBG_COMPARE_VW;

-- RECON_BBG_COMPARE -----------------------------------------------------------
-- Invoked by ExecuteRules via RULE_CATALOG.RULE_CATALOG_SOURCE. Returns
-- one row per BBG-compare rule, tagged with RULE_NAME so ExecuteRule can
-- attribute each row to its matching rule.
CREATE OR REPLACE PROCEDURE RECON_BBG_COMPARE(
    P_ALADDIN_ID   VARCHAR,
    P_ID_BB_GLOBAL VARCHAR
)
RETURNS TABLE(
    "RULE_NAME"         VARCHAR,
    "ALADDIN_ID"        VARCHAR,
    "ID_BB_GLOBAL"      VARCHAR,
    "BBG_VALUE"         VARCHAR,
    "ALADDIN_VALUE"     VARCHAR,
    "ISSUE_DESCRIPTION" VARCHAR
)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT
            'RULE_DM_BBG_MATURITY_DATE'::VARCHAR AS "RULE_NAME",
            :P_ALADDIN_ID::VARCHAR               AS "ALADDIN_ID",
            :P_ID_BB_GLOBAL::VARCHAR             AS "ID_BB_GLOBAL",
            '4/18/2029'::VARCHAR                 AS "BBG_VALUE",
            '5/15/2029'::VARCHAR                 AS "ALADDIN_VALUE",
            ('BBG Vs ALADDIN Maturity Date : ALADDIN Maturity :' ||
                '5/15/2029' || ' BBG Maturity:' || '4/18/2029')::VARCHAR
                                                 AS "ISSUE_DESCRIPTION"
        UNION ALL
        SELECT
            'RULE_DM_BBG_REGISTRATION'::VARCHAR,
            :P_ALADDIN_ID::VARCHAR,
            :P_ID_BB_GLOBAL::VARCHAR,
            'Reg S'::VARCHAR,
            '144A'::VARCHAR,
            ('BBG Vs ALADDIN Registration : ALADDIN Registration:' ||
                '144A' || ' BBG Registration:' || 'Reg S')::VARCHAR
    );
    RETURN TABLE(res);
END;
$$;

-- INSERT_EXCEPTION ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE INSERT_EXCEPTION(
    "RULE_ID"           NUMBER,
    "ASSET_ID"          VARCHAR,
    "EXCEPTION_DATE"    DATE,
    "ID_BB_GLOBAL"      VARCHAR,
    "STATUS_ID"         NUMBER,
    "EXCEPTION_TIME"    TIMESTAMP_NTZ,
    "ISSUE_DESCRIPTION" VARCHAR,
    "RESULT_DATA"       OBJECT,
    "ASSIGN_TO_ID"      NUMBER,
    "RESULT_TYPE_ID"    NUMBER,
    "CREATED_DATE"      TIMESTAMP_NTZ,
    "CREATED_BY"        VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    -- INSERT ... SELECT (not VALUES) so the COALESCE/NULLIF expression on
    -- STATUS_ID is evaluated by the query planner rather than the VALUES
    -- list, which rejects function calls against bound parameters in SF.
    INSERT INTO "EXCEPTION" (
        "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "ID_BB_GLOBAL",
        "STATUS_ID", "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "ASSIGN_TO_ID", "RESULT_TYPE_ID", "CREATED_DATE", "CREATED_BY"
    )
    SELECT
        :RULE_ID, :ASSET_ID, :EXCEPTION_DATE, :ID_BB_GLOBAL,
        COALESCE(NULLIF(:STATUS_ID, 0), 1),  -- default to Pending
        :EXCEPTION_TIME, :ISSUE_DESCRIPTION, :RESULT_DATA,
        :ASSIGN_TO_ID, :RESULT_TYPE_ID, :CREATED_DATE, :CREATED_BY;
    RETURN 'OK';
END;
$$;

-- UPDATE_EXCEPTION ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE UPDATE_EXCEPTION(
    P_RULE_ID           NUMBER,
    P_ASSET_ID          VARCHAR,
    P_EXCEPTION_DATE    DATE,
    P_ID_BB_GLOBAL      VARCHAR,
    P_STATUS_ID         NUMBER,
    P_EXCEPTION_TIME    TIMESTAMP_NTZ,
    P_ISSUE_DESCRIPTION VARCHAR,
    P_RESULT_DATA       OBJECT,
    P_ASSIGN_TO_ID      NUMBER,
    P_RESULT_TYPE_ID    NUMBER,
    P_CREATED_DATE      TIMESTAMP_NTZ,
    P_CREATED_BY        VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    UPDATE "EXCEPTION"
       SET "EXCEPTION_DATE"    = :P_EXCEPTION_DATE,
           "EXCEPTION_TIME"    = :P_EXCEPTION_TIME,
           "STATUS_ID"         = 1,  -- re-flagged -> Pending
           "ISSUE_DESCRIPTION" = :P_ISSUE_DESCRIPTION,
           "RESULT_DATA"       = COALESCE(:P_RESULT_DATA, "RESULT_DATA"),
           "ASSIGN_TO_ID"      = COALESCE(:P_ASSIGN_TO_ID, "ASSIGN_TO_ID"),
           "RESULT_TYPE_ID"    = :P_RESULT_TYPE_ID,
           "CREATED_DATE"      = :P_CREATED_DATE,
           "CREATED_BY"        = :P_CREATED_BY,
           "ID_BB_GLOBAL"      = COALESCE(:P_ID_BB_GLOBAL, "ID_BB_GLOBAL")
     WHERE "ASSET_ID" = :P_ASSET_ID
       AND "RULE_ID"  = :P_RULE_ID;
    RETURN 'OK';
END;
$$;

-- UPDATE_EXCEPTION_STATUS -----------------------------------------------------
-- Bumps MODIFIED_DATE / MODIFIED_BY on every matching row. Flips STATUS_ID
-- to 4 (Complete) only when P_COMPLETE is true.
CREATE OR REPLACE PROCEDURE UPDATE_EXCEPTION_STATUS(
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
       SET "STATUS_ID"     = CASE WHEN :P_COMPLETE THEN 4 ELSE "STATUS_ID" END,
           "MODIFIED_DATE" = CURRENT_TIMESTAMP::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "ASSET_ID"      = :P_ASSET_ID
       AND "RULE_ID"       = :P_RULE_ID;
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_ASSIGN_TO ------------------------------------------------------------
CREATE OR REPLACE PROCEDURE UPDATE_ASSIGN_TO(
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
CREATE OR REPLACE PROCEDURE GET_DM_USERS()
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
CREATE OR REPLACE PROCEDURE GET_RULE_GROUPS()
RETURNS TABLE("NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT "NAME"
        FROM "RULE_GROUP"
        ORDER BY "RULE_GROUP_ID" ASC
    );
    RETURN TABLE(res);
END;
$$;

-- GET_RULE_CATALOGS -----------------------------------------------------------
CREATE OR REPLACE PROCEDURE GET_RULE_CATALOGS(
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
-- Returns individual RULE_NAMEs belonging to a given catalog. Used by the
-- tcw-dqm tree view (Group -> Catalog -> Rule) since GET_RULES now returns
-- one row per catalog rather than one row per rule.
CREATE OR REPLACE PROCEDURE GET_RULE_NAMES(
    P_RULE_CATALOG VARCHAR
)
RETURNS TABLE("RULE_NAME" VARCHAR)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT r."RULE_NAME"
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
-- column per row). ENVIRONMENT is RULE_CATALOG_CONNECTION. P_PROCESS_TYPE
-- is accepted for caller compatibility but ignored.
--
-- Filtering:
--   P_RULE_TYPE = 'CATALOG' or 'RULE' (RULE behaves the same as CATALOG
--     for now) → P_RULE_NAME matches RULE_CATALOG.NAME.
--   P_RULE_TYPE = 'GROUP'  → P_RULE_NAME matches RULE_GROUP.NAME; returns
--     every catalog whose RULE_GROUP_ID resolves to that group.
--   P_RULE_NAME NULL / empty / 'All' → no filter, return every catalog.
CREATE OR REPLACE PROCEDURE GET_RULES(
    P_PROCESS_TYPE VARCHAR,
    P_RULE_NAME    VARCHAR DEFAULT NULL,
    P_RULE_TYPE    VARCHAR DEFAULT NULL
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

-- GET_EXCEPTION_STATUS --------------------------------------------------------
CREATE OR REPLACE PROCEDURE GET_EXCEPTION_STATUS()
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
CREATE OR REPLACE PROCEDURE GET_EXCEPTION_TYPE()
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
CREATE OR REPLACE PROCEDURE GET_PRIORITY_TYPE()
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
CREATE OR REPLACE PROCEDURE GET_SEVERITY_TYPE()
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
CREATE OR REPLACE PROCEDURE GET_EXCEPTIONS(
    P_ASSET_ID          VARCHAR DEFAULT NULL,
    P_EXCEPTION_TYPE    VARCHAR DEFAULT NULL,
    P_SEVERITY          VARCHAR DEFAULT NULL,
    P_PRIORITY          VARCHAR DEFAULT NULL,
    P_RULE_CATALOG      VARCHAR DEFAULT NULL,
    P_RULE_NAME         VARCHAR DEFAULT NULL,
    P_RULE_GROUP        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATUS  VARCHAR DEFAULT NULL,
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
    "STATUS_ID"         NUMBER,
    "EXCEPTION_STATUS"  VARCHAR,
    "COMMENT_ID"        NUMBER,
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
               e."STATUS_ID"               AS "STATUS_ID",
               es."NAME"                   AS "EXCEPTION_STATUS",
               e."COMMENT_ID"              AS "COMMENT_ID",
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
        LEFT JOIN "EXCEPTION_STATUS"        es  ON es."EXCEPTION_STATUS_ID"         = e."STATUS_ID"
        LEFT JOIN "DM_USER"                 du  ON du."ID"                          = e."ASSIGN_TO_ID"
        WHERE (:P_ASSET_ID          IS NULL OR e."ASSET_ID" = :P_ASSET_ID)
          AND (:P_EXCEPTION_TYPE    IS NULL OR et."NAME"    = :P_EXCEPTION_TYPE)
          AND (:P_SEVERITY          IS NULL OR est."NAME"   = :P_SEVERITY)
          AND (:P_PRIORITY          IS NULL OR ept."NAME"   = :P_PRIORITY)
          AND (:P_RULE_CATALOG      IS NULL OR :P_RULE_CATALOG  = 'All' OR rc."NAME" = :P_RULE_CATALOG)
          AND (:P_RULE_NAME         IS NULL OR :P_RULE_NAME  = 'All' OR r."RULE_NAME" = :P_RULE_NAME)
          AND (:P_RULE_GROUP        IS NULL OR :P_RULE_GROUP = 'All' OR rg."NAME" = :P_RULE_GROUP)
          AND (:P_EXCEPTION_STATUS  IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es."NAME" = :P_EXCEPTION_STATUS)
          AND (:P_ASSIGN_TO         IS NULL OR :P_ASSIGN_TO = 'All' OR du."USER" = :P_ASSIGN_TO)
          AND (:P_RULE_NAME_PATTERN IS NULL OR r."RULE_NAME" ILIKE :P_RULE_NAME_PATTERN)
    );
    RETURN TABLE(res);
END;
$$;

-- GET_ASSETS ------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE GET_ASSETS(
    P_EXCEPTION_TYPE   VARCHAR DEFAULT NULL,
    P_SEVERITY         VARCHAR DEFAULT NULL,
    P_PRIORITY         VARCHAR DEFAULT NULL,
    P_RULE_CATALOG     VARCHAR DEFAULT NULL,
    P_RULE_NAME        VARCHAR DEFAULT NULL,
    P_EXCEPTION_STATUS VARCHAR DEFAULT NULL,
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
                es."NAME"        AS status_name,
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
            LEFT JOIN "EXCEPTION_STATUS" es
              ON es."EXCEPTION_STATUS_ID" = e."STATUS_ID"
            LEFT JOIN "DM_USER" du
              ON du."ID" = e."ASSIGN_TO_ID"
            WHERE (:P_EXCEPTION_TYPE   IS NULL OR et."NAME"  = :P_EXCEPTION_TYPE)
              AND (:P_SEVERITY         IS NULL OR est."NAME" = :P_SEVERITY)
              AND (:P_PRIORITY         IS NULL OR ept."NAME" = :P_PRIORITY)
              AND (:P_RULE_GROUP       IS NULL OR :P_RULE_GROUP       = 'All' OR rg."NAME"      = :P_RULE_GROUP)
              AND (:P_RULE_CATALOG     IS NULL OR :P_RULE_CATALOG     = 'All' OR rc."NAME"      = :P_RULE_CATALOG)
              AND (:P_RULE_NAME        IS NULL OR :P_RULE_NAME        = 'All' OR r."RULE_NAME"  = :P_RULE_NAME)
              AND (:P_EXCEPTION_STATUS IS NULL OR :P_EXCEPTION_STATUS = 'All' OR es."NAME"      = :P_EXCEPTION_STATUS)
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
            COUNT_IF(COALESCE(status_name, '') <> 'Complete')      AS "EXCEPTION_COUNT",
            '10:55 AM'                                             AS "BBG_LAST_REFRESH",
            -- ALL_COMPLETE: asset-level property, true iff every EXCEPTION row
            -- for the asset (across all statuses, ignoring user filters) has
            -- status 'Complete'. Computed via a correlated subquery against
            -- the unfiltered EXCEPTION table.
            (SELECT COUNT(*) > 0
                    AND COUNT_IF(COALESCE(es_all."NAME", '') <> 'Complete') = 0
               FROM "EXCEPTION" e_all
               LEFT JOIN "EXCEPTION_STATUS" es_all
                 ON es_all."EXCEPTION_STATUS_ID" = e_all."STATUS_ID"
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
CREATE OR REPLACE PROCEDURE INSERT_SECURITY_EXCEPTION(
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
-- 5. MIGRATION SCRIPTS (one-time — DO NOT include in repeated rerun)
-- =============================================================================
-- These INSERT...SELECT scripts copy data from one table to another.
-- Rerunning them duplicates rows. Uncomment + run manually only when needed.

/*
-- Copy EXCEPTION snapshot into EXCEPTION_HIST.
INSERT INTO DATA_QUALITY.EXCEPTION_HIST (
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATUS_ID, COMMENT_ID, EXCEPTION_TIME, ISSUE_DESCRIPTION,
    RESULT_DATA, SUPPRESS_DATE, ASSIGN_TO_ID, RESULT_TYPE_ID,
    CREATED_DATE, CREATED_BY, MODIFIED_DATE, MODIFIED_BY
)
SELECT
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATUS_ID, COMMENT_ID, EXCEPTION_TIME, ISSUE_DESCRIPTION,
    RESULT_DATA, SUPPRESS_DATE, ASSIGN_TO_ID, RESULT_TYPE_ID,
    CREATED_DATE, CREATED_BY, MODIFIED_DATE, MODIFIED_BY
FROM DATA_QUALITY.EXCEPTION;


-- Initial backfill from legacy SECURITY_EXCEPTION (kept for reference; the
-- SECURITY_EXCEPTION table itself is no longer maintained here).
INSERT INTO DATA_QUALITY.EXCEPTION (
    EXCEPTION_ID, RULE_ID, ASSET_ID, EXCEPTION_DATE, ID_BB_GLOBAL,
    STATUS_ID, EXCEPTION_TIME, ISSUE_DESCRIPTION, ASSIGN_TO_ID,
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
