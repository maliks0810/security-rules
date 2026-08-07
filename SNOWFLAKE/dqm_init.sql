-- =============================================================================
-- dqm_init.sql
--
-- DDL-only Snowflake setup for the security-rules / DQM application.
-- Database: TCW_CORE_DEV, Schema: DATA_QUALITY.
-- This is the canonical "fresh environment" script — running it brings
-- the DATA_QUALITY schema to the tables / views / procs the Go service
-- expects. Seed data (INSERTs / UPDATEs / migration scripts) lives in
-- SNOWFLAKE/dqm_seed_data.sql; run that immediately after this file to
-- populate the lookup and operational tables.
--
-- RERUNNABILITY:
--   * Every object uses CREATE OR REPLACE — tables, views, procedures.
--   * Lookup AND operational tables (DM_USER, RULE_GROUP, RULE_CATALOG,
--     RULE, EXCEPTION, EXCEPTION_HIST, EXCEPTION_STATE, EXCEPTION_TYPE,
--     EXCEPTION_PRIORITY_TYPE, EXCEPTION_SEVERITY_TYPE) are dropped and
--     recreated on each run. Rerunning destroys existing row data in
--     those tables — that is the intended semantic for repeatable env
--     setup. To preserve production data on a specific table, comment
--     out its CREATE OR REPLACE block before running.
--
-- MAINTAINING THIS FILE:
--   When you add, update, or drop a Snowflake object referenced by
--   security-rules, also update the matching section here — this
--   combined script is the source of truth for setting up a new
--   environment (individual SNOWFLAKE/<name>.sql files remain as
--   per-object references). Any INSERT / UPDATE / DELETE / TRUNCATE
--   belongs in dqm_seed_data.sql, NOT here.
--   Sections are ordered to respect dependencies:
--     1. Lookup tables   2. Data tables   3. Views   4. Procedures
--
-- USAGE:
--   snowsql -f SNOWFLAKE/dqm_init.sql
--   snowsql -f SNOWFLAKE/dqm_seed_data.sql
--   The database/schema context is inherited from the caller's session —
--   USE DATABASE / USE SCHEMA yourself before running (or configure
--   default_database / default_schema on the SF role/user).
-- =============================================================================


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

-- EXCEPTION_TYPE --------------------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_TYPE (
    EXCEPTION_TYPE_ID INT,
    NAME              VARCHAR(100),
    SORT_ORDER        INT,
    CREATED_BY        VARCHAR(100),
    CREATED_DATE      TIMESTAMP_NTZ(9)
);

-- EXCEPTION_PRIORITY_TYPE -----------------------------------------------------
CREATE OR REPLACE TABLE EXCEPTION_PRIORITY_TYPE (
    EXCEPTION_PRIORITY_TYPE_ID INT,
    NAME                       VARCHAR(100),
    SORT_ORDER                 INT,
    CREATED_BY                 VARCHAR(100),
    CREATED_DATE               TIMESTAMP_NTZ(9)
);

-- EXCEPTION_SEVERITY_TYPE -----------------------------------------------------
-- Rows seeded from dqm_seed_data.sql; canonical severity categories used
-- by the assets grid. Adjust the VALUES list in dqm_seed_data.sql when
-- business adds/renames severity buckets.
CREATE OR REPLACE TABLE EXCEPTION_SEVERITY_TYPE (
    EXCEPTION_SEVERITY_TYPE_ID INT,
    NAME                       VARCHAR(100),
    SORT_ORDER                 INT,
    CREATED_BY                 VARCHAR(100),
    CREATED_DATE               TIMESTAMP_NTZ(9)
);


-- =============================================================================
-- 2. OPERATIONAL DATA TABLES (CREATE OR REPLACE â€” resets data on rerun)
-- =============================================================================

-- DM_USER ---------------------------------------------------------------------
CREATE OR REPLACE TABLE DM_USER (
    ID   NUMBER AUTOINCREMENT START 1 INCREMENT 1 PRIMARY KEY,
    "USER" VARCHAR(100) NOT NULL
);

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

-- RULE_CATALOG ----------------------------------------------------------------
CREATE OR REPLACE TABLE RULE_CATALOG (
    RULE_CATALOG_ID         NUMBER(38,0) IDENTITY(1,1) PRIMARY KEY,
    NAME                    VARCHAR(100),
    DESCRIPTION             VARCHAR(512),
    RULE_GROUP_ID           NUMBER(38,0),
    RULE_CATALOG_SOURCE     VARCHAR(4096),
    RULE_CATALOG_TYPE       VARCHAR(100),
    RULE_CATALOG_CONNECTION VARCHAR(1000),
    -- Optional stored-procedure name invoked to re-evaluate a catalog's
    -- non-New rows and revert any that no longer meet the exception
    -- criteria back to STATUS_ID = 1 ('New'). NULL means the catalog
    -- has no revert workflow. Populated for 'Bloomberg Compare
    -- Differences' with SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES
    -- (see dqm_seed_data.sql).
    REVERT_TO_NEW_CRITERIA  VARCHAR(200),
    CREATED_DATE            TIMESTAMP_NTZ(9),
    CREATED_BY              VARCHAR(100)
);

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
    -- Default assignee for every rule. Seeded / backfilled to 2 (the
    -- DM_USER row for the primary assignee). SP_GET_EXCEPTIONS and
    -- SP_GET_ASSETS source the Assign To grid column from here, not
    -- from EXCEPTION.ASSIGN_TO_ID, so per-rule ownership follows the
    -- rule instead of the per-row assignment.
    ASSIGN_TO_ID               INT NULL DEFAULT 2,
    CREATED_BY                 VARCHAR(100) NULL,
    CREATED_DATE               TIMESTAMP_NTZ(9) NULL
);

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
    -- Snapshot of the most recent CURRENT_DATE (UTC) on which the row
    -- carried STATUS_ID = 1 ("New"). Written by every INSERT (rows
    -- start New) and by every path that flips STATUS_ID back to 1
    -- (SP_UPDATE_EXCEPTION_STATUS, SP_UPDATE_BULK_STATUS,
    -- SP_EXPIRE_SUPPRESS_DATES, SP_INHERIT_EXCEPTION_STATUSES,
    -- SP_UPDATE_EXCEPTION). Any transition to a non-New status
    -- deliberately leaves OPEN_DATE untouched so the grid can show
    -- when the exception was last surfaced.
    OPEN_DATE         DATE,
    -- Companion to OPEN_DATE. Population semantics are declared in a
    -- follow-up (expected: stamped when STATUS_ID moves away from
    -- 'New' → Accept / Override / Suppress / Complete / …; cleared on
    -- transition back to 'New'). Column added first so the schema is
    -- in place before the write-path wiring lands.
    CLOSE_DATE        DATE,
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
    -- Copied straight through from EXCEPTION.OPEN_DATE by
    -- SP_ARCHIVE_EXCEPTIONS. History rows never get a fresh OPEN_DATE
    -- of their own — they carry the value the live row had at
    -- archive time.
    OPEN_DATE         DATE,
    -- Copied straight through from EXCEPTION.CLOSE_DATE by
    -- SP_ARCHIVE_EXCEPTIONS. Same carry-forward semantics as OPEN_DATE:
    -- history rows never get a fresh CLOSE_DATE of their own.
    CLOSE_DATE        DATE,
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

-- RULE_ASSIGN_OVERRIDE --------------------------------------------------------
-- Per-rule assignee override written by the Bulk Assign flow. Latest row
-- per RULE_ID wins in the grid: SP_GET_EXCEPTIONS / SP_GET_EXCEPTIONS_HIST
-- / SP_GET_ASSETS prefer this ASSIGN_TO_ID over RULE.ASSIGN_TO_ID for
-- rows where EXCEPTION.ASSIGN_TO_ID is NULL (per-row grid reassignment
-- still wins over the override). ASSIGN_TO_UNTIL_DATE is recorded but
-- not currently used to expire overrides — it is metadata for future
-- time-boxed assignments.
CREATE OR REPLACE TABLE RULE_ASSIGN_OVERRIDE (
    RULE_ASSIGN_OVERRIDE_ID NUMBER IDENTITY(1,1) PRIMARY KEY,
    RULE_ID                 INT NOT NULL,
    ASSIGN_TO_ID            INT NOT NULL,
    ASSIGN_TO_UNTIL_DATE    DATE,
    CREATED_BY              VARCHAR(100),
    CREATED_DATE            TIMESTAMP_NTZ(9)
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

-- ARCHIVE_STALE_DATES ---------------------------------------------------------
-- Housekeeping: moves any EXCEPTION rows whose EXCEPTION_DATE is
-- strictly older than today into EXCEPTION_HIST, so EXCEPTION only
-- holds the current day's rows. BATCH_ID is per (RULE_ID,
-- EXCEPTION_DATE): MAX(HIST.BATCH_ID for that rule+date) + 1 (defaults
-- to 1 when the pair has never been archived). Different rules on the
-- same date advance their batch counters independently. Called by an
-- external cron, not from the /executeRules service path.
CREATE OR REPLACE PROCEDURE SP_ARCHIVE_STALE_DATES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    exc_today DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected  NUMBER := 0;
BEGIN
    INSERT INTO "EXCEPTION_HIST" (
        "EXCEPTION_ID", "RULE_ID", "ASSET_ID", "EXCEPTION_DATE", "BATCH_ID",
        "ID_BB_GLOBAL", "STATE_ID", "STATUS_ID", "COMMENTS",
        "EXCEPTION_TIME", "ISSUE_DESCRIPTION", "RESULT_DATA",
        "SUPPRESS_DATE", "OPEN_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        e."EXCEPTION_ID", e."RULE_ID", e."ASSET_ID", e."EXCEPTION_DATE",
        COALESCE(
            (SELECT MAX(h."BATCH_ID") FROM "EXCEPTION_HIST" h
              WHERE h."EXCEPTION_DATE" = e."EXCEPTION_DATE"
                AND h."RULE_ID"        = e."RULE_ID"),
            0
        ) + 1 AS "BATCH_ID",
        e."ID_BB_GLOBAL", e."STATE_ID", e."STATUS_ID", e."COMMENTS",
        e."EXCEPTION_TIME", e."ISSUE_DESCRIPTION", e."RESULT_DATA",
        e."SUPPRESS_DATE", e."OPEN_DATE", e."ASSIGN_TO_ID", e."RESULT_TYPE_ID",
        e."CREATED_DATE", e."CREATED_BY", e."MODIFIED_DATE", e."MODIFIED_BY"
    FROM "EXCEPTION" e
    WHERE e."EXCEPTION_DATE" < :exc_today;
    affected := SQLROWCOUNT;

    DELETE FROM "EXCEPTION" WHERE "EXCEPTION_DATE" < :exc_today;

    RETURN affected;
END;
$$;

CREATE OR REPLACE PROCEDURE SP_ARCHIVE_EXCEPTIONS(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    exc_date   DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
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
        "SUPPRESS_DATE", "OPEN_DATE", "ASSIGN_TO_ID", "RESULT_TYPE_ID",
        "CREATED_DATE", "CREATED_BY", "MODIFIED_DATE", "MODIFIED_BY"
    )
    SELECT
        e."EXCEPTION_ID", e."RULE_ID", e."ASSET_ID", e."EXCEPTION_DATE", :next_batch,
        e."ID_BB_GLOBAL", e."STATE_ID", e."STATUS_ID", e."COMMENTS",
        e."EXCEPTION_TIME", e."ISSUE_DESCRIPTION", e."RESULT_DATA",
        e."SUPPRESS_DATE", e."OPEN_DATE", e."ASSIGN_TO_ID", e."RESULT_TYPE_ID",
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

-- UPDATE_CLOSE_DATE -----------------------------------------------------------
-- Stamps CLOSE_DATE = today on any EXCEPTION_HIST row that represents
-- a (RULE_ID, ASSET_ID) exception that no longer surfaces in the live
-- EXCEPTION table. Intended to run after ExecuteRules has finished
-- archive → insert → inherit → revert. "Previous batch" per
-- (RULE_ID, ASSET_ID) resolves via max (EXCEPTION_DATE, BATCH_ID) —
-- today's later batches win when today has archives; falls through to
-- yesterday's final batch on the first run of a fresh day. Idempotent
-- (skips rows whose CLOSE_DATE is already set). Returns rows stamped.
CREATE OR REPLACE PROCEDURE SP_UPDATE_CLOSE_DATE()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    today            DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    disappeared      NUMBER := 0;
    accept_research  NUMBER := 0;
    reopened_new     NUMBER := 0;
BEGIN
    -- Pass 1: (RULE_ID, ASSET_ID) present in HIST but no longer in EXCEPTION.
    -- Stamp CLOSE_DATE on that combo's latest hist row.
    UPDATE "EXCEPTION_HIST" h
       SET "CLOSE_DATE" = :today
      FROM (
          SELECT "EXCEPTION_ID", "RULE_ID", "ASSET_ID"
            FROM (
                SELECT "EXCEPTION_ID", "RULE_ID", "ASSET_ID",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
            )
           WHERE rn = 1
      ) latest
     WHERE h."EXCEPTION_ID" = latest."EXCEPTION_ID"
       AND h."CLOSE_DATE"   IS NULL
       AND NOT EXISTS (
           SELECT 1
             FROM "EXCEPTION" e
            WHERE e."RULE_ID"  = latest."RULE_ID"
              AND e."ASSET_ID" = latest."ASSET_ID"
       );
    disappeared := SQLROWCOUNT;

    -- Pass 2: live EXCEPTION rows currently in status 'Accept' or
    -- 'Research' whose CLOSE_DATE is NULL. Belt-and-suspenders alongside
    -- SP_UPDATE_EXCEPTION_STATUS / SP_UPDATE_BULK_STATUS (which stamp
    -- CLOSE_DATE on the transition itself). Catches inherited-status
    -- rows — SP_INHERIT_EXCEPTION_STATUSES pulls STATUS_ID forward from
    -- hist without touching CLOSE_DATE — and any row that took the
    -- transition before CLOSE_DATE existed as a column. Idempotent
    -- through the IS NULL guard.
    UPDATE "EXCEPTION" e
       SET "CLOSE_DATE" = :today
     WHERE e."CLOSE_DATE" IS NULL
       AND e."STATUS_ID" IN (
           SELECT "EXCEPTION_STATUS_ID"
             FROM "EXCEPTION_STATUS"
            WHERE "NAME" IN ('Accept', 'Research')
       );
    accept_research := SQLROWCOUNT;

    -- Pass 3: live EXCEPTION rows currently in an unresolved /
    -- pending status ('New' / 'Suppress' / 'Challenge') whose
    -- CLOSE_DATE is still populated from a previous Accept / Research
    -- run. Clear it so the grid doesn't show one of these statuses
    -- carrying a stale close date. Idempotent via IS NOT NULL guard.
    -- Covers reopens via operator flip, SP_REVERT_TO_NEW_BLOOMBERG_
    -- COMPARE_DIFFERENCES, SP_EXPIRE_SUPPRESS_DATES, inherited status,
    -- and any pre-CLOSE_DATE-column rows.
    UPDATE "EXCEPTION" e
       SET "CLOSE_DATE" = NULL
     WHERE e."CLOSE_DATE" IS NOT NULL
       AND e."STATUS_ID" IN (
           SELECT "EXCEPTION_STATUS_ID"
             FROM "EXCEPTION_STATUS"
            WHERE "NAME" IN ('New', 'Suppress', 'Challenge')
       );
    reopened_new := SQLROWCOUNT;

    RETURN disappeared + accept_research + reopened_new;
END;
$$;

-- INHERIT_EXCEPTION_STATUSES --------------------------------------------------
-- For each EXCEPTION row in scope, carry the last-known STATUS_ID from
-- EXCEPTION_HIST forward, keyed by (RULE_ID, ASSET_ID). Row picked by
-- (EXCEPTION_DATE DESC, BATCH_ID DESC) — today's max batch wins when
-- today has archives; else falls back to the most recent prior date's
-- max batch, so the first run of a new day inherits the last run of
-- the previous day (once SP_ARCHIVE_STALE_DATES has swept it).
-- Scope semantics match SP_GET_RULES (post-CATALOG/RULE split):
--   CATALOG → RULE_CATALOG.NAME
--   GROUP   → RULE_GROUP.NAME
--   RULE    → RULE.RULE_NAME
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
           -- OPEN_DATE moves to today only when this inherit flips the
           -- row TO 'New' (STATUS_ID = 1). Inheriting Accept / Override
           -- / Suppress leaves the last-New date alone.
           "OPEN_DATE"     = CASE
                                 WHEN h."STATUS_ID" = 1
                                     THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
                                 ELSE e."OPEN_DATE"
                             END,
           -- CLOSE_DATE carries over from the last EXCEPTION_HIST row
           -- for the same (RULE_ID, ASSET_ID) so the day the row was
           -- originally closed survives the archive → insert → inherit
           -- cycle. NULL on the hist side leaves the live row's date
           -- alone (via COALESCE). Pass 2 of SP_UPDATE_CLOSE_DATE
           -- backstops the case where hist has no CLOSE_DATE yet but
           -- the current status is Accept / Research.
           "CLOSE_DATE"    = COALESCE(h."CLOSE_DATE", e."CLOSE_DATE"),
           -- COMMENTS carry over from the last EXCEPTION_HIST row for
           -- the same (RULE_ID, ASSET_ID). Anything the operator typed
           -- while the row sat in Accept / Suppress / Override / … is
           -- preserved across rule re-runs. NULL / empty on the hist
           -- side leaves the live row's comment alone via COALESCE so
           -- a cleared comment on the hist side doesn't blank an
           -- unrelated freshly-typed live comment.
           "COMMENTS"      = COALESCE(h."COMMENTS", e."COMMENTS"),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
      FROM (
          SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS", "CLOSE_DATE"
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "STATUS_ID", "COMMENTS", "CLOSE_DATE",
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
       AND (e."STATUS_ID" IS NULL
            OR e."STATUS_ID" <> h."STATUS_ID"
            OR (h."COMMENTS" IS NOT NULL
                AND NOT EQUAL_NULL(e."COMMENTS", h."COMMENTS"))
            OR (h."CLOSE_DATE" IS NOT NULL
                AND NOT EQUAL_NULL(e."CLOSE_DATE", h."CLOSE_DATE")))
       AND e."EXCEPTION_ID" IN (
           SELECT e2."EXCEPTION_ID"
             FROM "EXCEPTION" e2
             JOIN "RULE"          r  ON r."RULE_ID"          = e2."RULE_ID"
             JOIN "RULE_CATALOG"  rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
             LEFT JOIN "RULE_GROUP" rg ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
            WHERE :P_RULE_NAME IS NULL
               OR :P_RULE_NAME = ''
               OR :P_RULE_NAME = 'All'
               OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) = 'CATALOG'
                     AND rc."NAME" = :P_RULE_NAME)
               OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                     AND rg."NAME"  = :P_RULE_NAME)
               OR (UPPER(:P_RULE_TYPE) = 'RULE'
                     AND r."RULE_NAME" = :P_RULE_NAME)
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
        "STATUS_ID", "OPEN_DATE"
    )
    SELECT
        :RULE_ID, :ASSET_ID, :EXCEPTION_DATE, :ID_BB_GLOBAL,
        COALESCE(NULLIF(:STATE_ID, 0), 1),  -- default to Pending
        :EXCEPTION_TIME, :ISSUE_DESCRIPTION, :RESULT_DATA,
        :ASSIGN_TO_ID, :RESULT_TYPE_ID, :CREATED_DATE, :CREATED_BY,
        COALESCE(NULLIF(:STATUS_ID, 0), 1),  -- default to New
        -- OPEN_DATE: stamped with today only when the row starts as
        -- "New" (STATUS_ID = 1). Non-New inserts leave it NULL so the
        -- next transition-to-New sets it.
        CASE WHEN COALESCE(NULLIF(:STATUS_ID, 0), 1) = 1
             THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
             ELSE NULL
        END;
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
           "STATUS_ID"         = COALESCE(:P_STATUS_ID, "STATUS_ID"),
           -- OPEN_DATE ratchets only when the row's new STATUS_ID is 1
           -- (New). Any other transition — or a no-op status update —
           -- preserves the last-New date.
           "OPEN_DATE"         = CASE
                                     WHEN COALESCE(:P_STATUS_ID, "STATUS_ID") = 1
                                         THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
                                     ELSE "OPEN_DATE"
                                 END
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
           "MODIFIED_DATE" = CURRENT_TIMESTAMP()::TIMESTAMP_NTZ,
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
--
-- Optional P_COMMENTS / P_SUPPRESS_DATE let the caller bundle a
-- pending comment + suppress date the operator just typed but hasn't
-- committed via the per-cell endpoints yet — needed because
-- CommentsCell only commits on blur and SuppressDateCell's separate
-- commit is async, so a status change fired immediately after would
-- otherwise race and hit the "blank" guard against a stale DB row.
--   NULL / omitted → leave the column alone (existing DB value stays).
--   Any non-null   → applied atomically inside this same UPDATE.
-- Empty-string COMMENTS still passes through as "" (interpreted as
-- clear on non-New will trigger the guard).
--
-- Side effect for 'Accept': the row is snapshotted into EXCEPTION_OVERRIDE.
CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_STATUS(
    P_EXCEPTION_ID  NUMBER,
    P_STATUS_NAME   VARCHAR,
    P_COMMENTS      VARCHAR DEFAULT NULL,
    P_SUPPRESS_DATE DATE    DEFAULT NULL
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
           -- COMMENTS: apply the passed value when provided (non-null),
           -- else leave the existing DB value alone. Same NULL-vs-value
           -- convention as SP_UPDATE_BULK_STATUS.
           "COMMENTS"      = COALESCE(:P_COMMENTS, "COMMENTS"),
           -- SUPPRESS_DATE: only 'Suppress' keeps a value. When
           -- P_SUPPRESS_DATE is passed and the target status is
           -- Suppress, use it; otherwise fall back to the existing
           -- DB value. Moving off Suppress (to New / Accept /
           -- Override / …) clears the date so the grid never shows
           -- a stale suppression next to a non-Suppress row.
           "SUPPRESS_DATE" = CASE
                                 WHEN :P_STATUS_NAME = 'Suppress'
                                     THEN COALESCE(:P_SUPPRESS_DATE, "SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           -- OPEN_DATE ratchets when the row transitions TO 'New';
           -- otherwise the last-New date is preserved so the grid can
           -- show when the exception was originally surfaced.
           "OPEN_DATE"     = CASE
                                 WHEN :P_STATUS_NAME = 'New'
                                     THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
                                 ELSE "OPEN_DATE"
                             END,
           -- CLOSE_DATE stamps today when the row is closed via a
           -- transition to 'Accept' or 'Research'. Any other status
           -- transition (New / Suppress / Override / Complete)
           -- preserves the previous CLOSE_DATE — flipping back to New
           -- does NOT clear it, since the historical close date is
           -- useful even for a reopened row.
           "CLOSE_DATE"    = CASE
                                 WHEN :P_STATUS_NAME IN ('Accept', 'Research')
                                     THEN TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))
                                 -- Transitions to 'New' / 'Suppress' /
                                 -- 'Challenge' put the row back into
                                 -- an unresolved / pending state, so
                                 -- the historical close date is no
                                 -- longer valid and gets cleared.
                                 WHEN :P_STATUS_NAME IN ('New', 'Suppress', 'Challenge')
                                     THEN NULL
                                 ELSE "CLOSE_DATE"
                             END,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID
       AND EXISTS (
           SELECT 1 FROM "EXCEPTION_STATUS" WHERE "NAME" = :P_STATUS_NAME
       )
       -- Guards check the *effective* value (the passed param when
       -- present, else the existing DB value) so a bundled comment /
       -- suppress date the operator just typed satisfies the rule
       -- without needing the per-cell commit to land first.
       AND NOT (:P_STATUS_NAME = 'Suppress'
                AND COALESCE(:P_SUPPRESS_DATE, "SUPPRESS_DATE") IS NULL)
       AND NOT (:P_STATUS_NAME <> 'New'
                AND (COALESCE(:P_COMMENTS, "COMMENTS") IS NULL
                     OR COALESCE(:P_COMMENTS, "COMMENTS") = ''));
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
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
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
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
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
           -- Every row this touches transitions back to STATUS_ID=1
           -- (New), so OPEN_DATE ratchets to today.
           "OPEN_DATE"     = TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "SUPPRESS_DATE" IS NOT NULL
       AND "SUPPRESS_DATE" < TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES ---------------------------------
-- Bloomberg-catalog-scoped revert workflow. For every EXCEPTION row in
-- the 'Bloomberg Compare Differences' catalog that is not currently
-- 'New', flip it back to New (with OPEN_DATE = today) when EITHER of
-- the two RESULT_DATA JSON values has drifted since the previous run:
--   * ALADDIN_VALUE differs from the last archived hist row's value, OR
--   * BBG_VALUE     differs from the last archived hist row's value.
-- "Previous run" = the EXCEPTION_HIST row with the max
-- (EXCEPTION_DATE, BATCH_ID) per (RULE_ID, ASSET_ID). Same day's later
-- batches win when today has archives; falls through to yesterday's
-- final batch on the first run of a fresh day.
--
-- Additionally, any Suppress row whose SUPPRESS_DATE has passed
-- (< today UTC) reverts to New regardless of value drift and its
-- SUPPRESS_DATE is cleared. This duplicates SP_EXPIRE_SUPPRESS_DATES's
-- global sweep but keeps the Bloomberg revert workflow self-contained
-- for callers that invoke this SP directly (Rule Catalog's
-- REVERT_TO_NEW_CRITERIA).
--
-- Returns the total number of EXCEPTION rows reverted (drift + suppress
-- combined).
CREATE OR REPLACE PROCEDURE SP_REVERT_TO_NEW_BLOOMBERG_COMPARE_DIFFERENCES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    today             DATE          := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    now_ts            TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    suppress_id       NUMBER        := NULL;
    drift_affected    NUMBER        := 0;
    suppress_affected NUMBER        := 0;
BEGIN
    SELECT "EXCEPTION_STATUS_ID" INTO :suppress_id
    FROM "EXCEPTION_STATUS"
    WHERE "NAME" = 'Suppress'
    LIMIT 1;

    -- Pass 1: ALADDIN_VALUE / BBG_VALUE drift vs the latest hist row.
    UPDATE "EXCEPTION" e
       SET "STATUS_ID"     = 1,
           "OPEN_DATE"     = :today,
           "SUPPRESS_DATE" = NULL,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
      FROM (
          SELECT h."RULE_ID",
                 h."ASSET_ID",
                 TRY_PARSE_JSON(h."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR AS hist_aladdin,
                 TRY_PARSE_JSON(h."RESULT_DATA"):"BBG_VALUE"::VARCHAR     AS hist_bbg
            FROM (
                SELECT "RULE_ID", "ASSET_ID", "RESULT_DATA",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID", "ASSET_ID"
                           ORDER BY "EXCEPTION_DATE" DESC NULLS LAST,
                                    "BATCH_ID"       DESC NULLS LAST
                       ) AS rn
                  FROM "EXCEPTION_HIST"
            ) h
           WHERE h.rn = 1
      ) prev
     WHERE e."RULE_ID"  = prev."RULE_ID"
       AND e."ASSET_ID" = prev."ASSET_ID"
       AND e."STATUS_ID" <> 1
       AND e."RULE_ID" IN (
           SELECT r."RULE_ID"
             FROM "RULE" r
             JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
            WHERE rc."NAME" = 'Bloomberg Compare Differences'
       )
       AND (
           NOT EQUAL_NULL(
               TRY_PARSE_JSON(e."RESULT_DATA"):"ALADDIN_VALUE"::VARCHAR,
               prev.hist_aladdin
           )
           OR NOT EQUAL_NULL(
               TRY_PARSE_JSON(e."RESULT_DATA"):"BBG_VALUE"::VARCHAR,
               prev.hist_bbg
           )
       );
    drift_affected := SQLROWCOUNT;

    -- Pass 2: Suppress rows whose SUPPRESS_DATE has passed. Independent
    -- of hist so rows with no prior hist still get expired.
    -- OPEN_DATE is intentionally NOT ratcheted here — a suppression
    -- lapsing is not the same signal as a fresh discovery, so the
    -- original open date is preserved to keep the aging metric honest.
    IF (:suppress_id IS NOT NULL) THEN
        UPDATE "EXCEPTION" e
           SET "STATUS_ID"     = 1,
               "SUPPRESS_DATE" = NULL,
               "MODIFIED_DATE" = :now_ts,
               "MODIFIED_BY"   = 'system'
         WHERE e."STATUS_ID"    = :suppress_id
           AND e."SUPPRESS_DATE" IS NOT NULL
           AND e."SUPPRESS_DATE" < :today
           AND e."RULE_ID" IN (
               SELECT r."RULE_ID"
                 FROM "RULE" r
                 JOIN "RULE_CATALOG" rc ON rc."RULE_CATALOG_ID" = r."RULE_CATALOG_ID"
                WHERE rc."NAME" = 'Bloomberg Compare Differences'
           );
        suppress_affected := SQLROWCOUNT;
    END IF;

    RETURN drift_affected + suppress_affected;
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
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
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
           "MODIFIED_DATE" = CURRENT_TIMESTAMP()::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "ASSET_ID" = :P_ASSET_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_BULK_ASSIGN ----------------------------------------------------------
-- Bulk-assigns a user to every EXCEPTION belonging to any of the passed
-- rule names. The per-rule assignee is persisted in one of two places
-- depending on P_IS_PERMANENT:
--   FALSE (default) — INSERT one RULE_ASSIGN_OVERRIDE row per rule
--                     (soft override; RULE.ASSIGN_TO_ID untouched).
--                     Later runs pick up the override via the rao join
--                     in SP_GET_EXCEPTIONS / _HIST / _ASSETS.
--   TRUE            — UPDATE RULE.ASSIGN_TO_ID directly for every
--                     matched rule (permanent change to the rule
--                     default). No RULE_ASSIGN_OVERRIDE row is written.
--
-- Inputs:
--   P_RULE_NAMES  — comma-separated RULE_NAME list.
--   P_ASSIGN_TO   — DM_USER."USER" display name; resolved to DM_USER.ID
--                   the same way as SP_UPDATE_EXCEPTION_ASSIGN_TO.
--   P_IS_PERMANENT — TRUE writes to RULE.ASSIGN_TO_ID; FALSE (default)
--                   writes to RULE_ASSIGN_OVERRIDE.
--
-- Regardless of P_IS_PERMANENT, EXCEPTION.ASSIGN_TO_ID is updated for
-- every existing row so the current grid immediately reflects the new
-- assignee. Returns the number of EXCEPTION rows updated.
CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_ASSIGN(
    P_RULE_NAMES  VARCHAR,
    P_ASSIGN_TO   VARCHAR,
    P_IS_PERMANENT BOOLEAN DEFAULT FALSE
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    user_id  NUMBER := NULL;
    today    DATE   := TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    now_ts   TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    affected NUMBER := 0;
BEGIN
    IF (:P_ASSIGN_TO IS NULL OR :P_ASSIGN_TO = '') THEN
        RETURN 0;
    END IF;

    SELECT "ID" INTO :user_id
    FROM "DM_USER"
    WHERE "USER" = :P_ASSIGN_TO
    LIMIT 1;

    IF (:user_id IS NULL) THEN
        RETURN 0;
    END IF;

    IF (:P_RULE_NAMES IS NULL OR :P_RULE_NAMES = '') THEN
        RETURN 0;
    END IF;

    IF (:P_IS_PERMANENT) THEN
        -- RULE has no MODIFIED_DATE / MODIFIED_BY columns (see RULE.sql),
        -- so only the assignee is set here. The permanent write becomes
        -- the new rule default; SP_GET_EXCEPTIONS / _HIST / _ASSETS
        -- pick it up via the r."ASSIGN_TO_ID" leg of the COALESCE
        -- when no per-row or rao override wins.
        UPDATE "RULE"
           SET "ASSIGN_TO_ID" = :user_id
         WHERE "RULE_NAME" IN (
            SELECT TRIM(t.VALUE::STRING)
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
         );

        -- Purge any pre-existing soft overrides for these rules —
        -- once the rule default is set permanently, a stale rao row
        -- pointing at a different user would still win over
        -- RULE.ASSIGN_TO_ID via the COALESCE precedence and silently
        -- override the permanent assignment. Deleting them keeps
        -- the RULE row as the sole source of truth.
        DELETE FROM "RULE_ASSIGN_OVERRIDE"
         WHERE "RULE_ID" IN (
            SELECT r."RULE_ID"
            FROM "RULE" r
            JOIN (
                SELECT TRIM(t.VALUE::STRING) AS rule_name
                FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
                WHERE TRIM(t.VALUE::STRING) <> ''
            ) req
              ON r."RULE_NAME" = req.rule_name
         );
    ELSE
        INSERT INTO "RULE_ASSIGN_OVERRIDE" (
            "RULE_ID", "ASSIGN_TO_ID", "ASSIGN_TO_UNTIL_DATE",
            "CREATED_BY", "CREATED_DATE"
        )
        SELECT r."RULE_ID",
               :user_id,
               :today,
               'system',
               :now_ts
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name;
    END IF;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE "RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM LATERAL SPLIT_TO_TABLE(:P_RULE_NAMES, ',') t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name
     );

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;

-- UPDATE_BULK_STATUS ----------------------------------------------------------
-- Bulk-updates STATUS_ID (plus optional COMMENTS + SUPPRESS_DATE) for
-- every EXCEPTION belonging to any of the passed rule names.
--
-- Inputs:
--   P_RULE_NAMES   — comma-separated RULE_NAME list (same shape as
--                    SP_UPDATE_BULK_ASSIGN).
--   P_STATUS       — EXCEPTION_STATUS."NAME" (e.g. 'New', 'Accept',
--                    'Suppress', 'Override', 'Complete'). Unknown /
--                    empty → RETURN 0, no writes.
--   P_COMMENTS     — text written to EXCEPTION.COMMENTS on every
--                    matched row. Pass '' to clear, NULL to leave
--                    existing comments untouched.
--   P_SUPPRESS_DATE — 'YYYY-MM-DD' string written to
--                    EXCEPTION.SUPPRESS_DATE on every matched row.
--                    Pass NULL or '' to leave existing suppress dates
--                    untouched (there is no bulk-clear affordance on
--                    the Bulk Status panel).
--
-- Only current-day EXCEPTION rows are touched — the Bulk Status button
-- is gated to the current date on the client (see DqMonitorPage
-- showBulkAssign wiring), so this SP intentionally does not filter
-- EXCEPTION_DATE server-side; the client's gate is authoritative.
--
-- Returns the number of EXCEPTION rows updated.
CREATE OR REPLACE PROCEDURE SP_UPDATE_BULK_STATUS(
    P_RULE_NAMES   VARCHAR,
    P_STATUS       VARCHAR,
    P_COMMENTS     VARCHAR,
    P_SUPPRESS_DATE VARCHAR DEFAULT NULL
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    status_id NUMBER := NULL;
    now_ts    TIMESTAMP_NTZ := CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ;
    affected  NUMBER := 0;
    -- Resolve to a DATE up front so the UPDATE stays flat. NULLIF turns
    -- '' into NULL so an empty string from the client is treated as
    -- "leave suppress_date untouched" (parity with COMMENTS).
    parsed_suppress DATE := TRY_TO_DATE(NULLIF(:P_SUPPRESS_DATE, ''));
BEGIN
    IF (:P_RULE_NAMES IS NULL OR :P_RULE_NAMES = '') THEN
        RETURN 0;
    END IF;

    -- P_STATUS is now optional — Bulk Status can be used to update
    -- only COMMENTS (via the "Clear Comments" checkbox or a typed
    -- value). Reject only when the caller asked for nothing at all:
    -- no status, no comment change, no suppress date.
    IF ( (:P_STATUS IS NULL OR :P_STATUS = '')
         AND :P_COMMENTS IS NULL
         AND :parsed_suppress IS NULL
       ) THEN
        RETURN 0;
    END IF;

    -- Mirror the per-row grid rule (see ExceptionsTable status
    -- <select> onChange): moving an exception INTO 'Suppress'
    -- requires a Suppress Date. In bulk we can't rely on per-row
    -- existing dates because some rows may have never been
    -- suppressed. Require the caller to pass P_SUPPRESS_DATE
    -- explicitly and reject otherwise. The frontend disables the
    -- Update Status/Comments button in the same state; this is the
    -- server-side safety net.
    IF (UPPER(:P_STATUS) = 'SUPPRESS' AND :parsed_suppress IS NULL) THEN
        RETURN 0;
    END IF;

    -- Mirror the per-row grid rule: any transition AWAY from 'New'
    -- (Accept / Override / Hold / Suppress / Research / Challenge /
    -- …) must carry an operator comment. In bulk we require the
    -- caller to pass a non-empty P_COMMENTS so every matched row
    -- gets a comment; without it, the audit trail on a triaged row
    -- would be empty. Comments-only updates (P_STATUS blank) bypass
    -- this check. Parity with SP_UPDATE_EXCEPTION_STATUS.
    IF (:P_STATUS IS NOT NULL AND :P_STATUS <> ''
        AND UPPER(:P_STATUS) <> 'NEW'
        AND (:P_COMMENTS IS NULL OR :P_COMMENTS = '')) THEN
        RETURN 0;
    END IF;

    -- Only resolve the status id when a status was actually passed.
    -- A blank P_STATUS means "leave STATUS_ID alone", so we skip the
    -- lookup and let status_id stay NULL for the COALESCE below.
    IF (:P_STATUS IS NOT NULL AND :P_STATUS <> '') THEN
        SELECT "EXCEPTION_STATUS_ID" INTO :status_id
        FROM "EXCEPTION_STATUS"
        WHERE "NAME" = :P_STATUS
        LIMIT 1;

        IF (:status_id IS NULL) THEN
            RETURN 0;
        END IF;
    END IF;

    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = COALESCE(:status_id, "STATUS_ID"),
           "COMMENTS"      = COALESCE(:P_COMMENTS, "COMMENTS"),
           -- SUPPRESS_DATE handling:
           --   status change absent  → leave the date alone (a
           --     comments-only update must not disturb Suppress rows).
           --   status becomes 'Suppress' → use the passed date, else
           --     keep the existing one.
           --   any other status      → NULL out the date so the grid
           --     never shows a stale suppression next to a
           --     non-Suppress row.
           "SUPPRESS_DATE" = CASE
                                 WHEN :status_id IS NULL
                                     THEN "SUPPRESS_DATE"
                                 WHEN UPPER(:P_STATUS) = 'SUPPRESS'
                                     THEN COALESCE(:parsed_suppress, "SUPPRESS_DATE")
                                 ELSE NULL
                             END,
           -- OPEN_DATE ratchets only when this bulk update flips the
           -- row TO 'New'. Comments-only updates (status_id NULL) and
           -- transitions to any other status leave the last-New date
           -- intact.
           "OPEN_DATE"     = CASE
                                 WHEN :status_id IS NOT NULL
                                      AND UPPER(:P_STATUS) = 'NEW'
                                     THEN TO_DATE(:now_ts)
                                 ELSE "OPEN_DATE"
                             END,
           -- CLOSE_DATE stamps today when this bulk update flips the
           -- row TO 'Accept' or 'Research'. Comments-only updates and
           -- transitions to any other status preserve the previous
           -- CLOSE_DATE (parity with SP_UPDATE_EXCEPTION_STATUS).
           "CLOSE_DATE"    = CASE
                                 WHEN :status_id IS NOT NULL
                                      AND UPPER(:P_STATUS) IN ('ACCEPT', 'RESEARCH')
                                     THEN TO_DATE(:now_ts)
                                 -- Transitions to 'New' / 'Suppress' /
                                 -- 'Challenge' put the row back into
                                 -- an unresolved / pending state, so
                                 -- the historical close date is no
                                 -- longer valid and gets cleared.
                                 WHEN :status_id IS NOT NULL
                                      AND UPPER(:P_STATUS) IN ('NEW', 'SUPPRESS', 'CHALLENGE')
                                     THEN NULL
                                 ELSE "CLOSE_DATE"
                             END,
           "MODIFIED_DATE" = :now_ts,
           "MODIFIED_BY"   = 'system'
     WHERE "RULE_ID" IN (
        SELECT r."RULE_ID"
        FROM "RULE" r
        JOIN (
            SELECT TRIM(t.VALUE::STRING) AS rule_name
            FROM TABLE(SPLIT_TO_TABLE(:P_RULE_NAMES, ',')) t
            WHERE TRIM(t.VALUE::STRING) <> ''
        ) req
          ON r."RULE_NAME" = req.rule_name
     );

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
--   P_RULE_TYPE = 'CATALOG' → P_RULE_NAME matches RULE_CATALOG.NAME.
--   P_RULE_TYPE = 'GROUP'   → P_RULE_NAME matches RULE_GROUP.NAME; returns
--                              every catalog whose RULE_GROUP_ID resolves
--                              to that group.
--   P_RULE_TYPE = 'RULE'    → P_RULE_NAME matches RULE.RULE_NAME; returns
--                              the catalog(s) that own that rule
--                              (EXISTS-join keeps the catalog row unique).
--   P_RULE_NAME NULL / empty / 'All' → no filter, return every catalog.
CREATE OR REPLACE PROCEDURE SP_GET_RULES(
    P_RULE_NAME VARCHAR DEFAULT NULL,
    P_RULE_TYPE VARCHAR DEFAULT NULL
)
RETURNS TABLE(
    "RULE_CATALOG_ID"        NUMBER,
    "RULE_CATALOG_NAME"      VARCHAR,
    "RULE_COMMAND"           VARCHAR,
    "ENVIRONMENT"            VARCHAR,
    "REVERT_TO_NEW_CRITERIA" VARCHAR
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
               rc."RULE_CATALOG_CONNECTION" AS "ENVIRONMENT",
               rc."REVERT_TO_NEW_CRITERIA"  AS "REVERT_TO_NEW_CRITERIA"
        FROM "RULE_CATALOG" rc
        LEFT JOIN "RULE_GROUP" rg
          ON rg."RULE_GROUP_ID" = rc."RULE_GROUP_ID"
        WHERE :P_RULE_NAME IS NULL
           OR :P_RULE_NAME = ''
           OR :P_RULE_NAME = 'All'
           OR (UPPER(COALESCE(:P_RULE_TYPE, 'CATALOG')) = 'CATALOG'
                 AND rc."NAME" = :P_RULE_NAME)
           OR (UPPER(:P_RULE_TYPE) = 'GROUP'
                 AND rg."NAME"  = :P_RULE_NAME)
           OR (UPPER(:P_RULE_TYPE) = 'RULE'
                 AND EXISTS (
                     SELECT 1 FROM "RULE" r
                      WHERE r."RULE_CATALOG_ID" = rc."RULE_CATALOG_ID"
                        AND r."RULE_NAME"       = :P_RULE_NAME
                 ))
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
    P_RULE_NAME_PATTERN VARCHAR DEFAULT NULL,
    -- EXCEPTION_DATE cut-off (defaults to today UTC when NULL) so the
    -- grid never surfaces stale-date rows that haven't been swept to
    -- EXCEPTION_HIST yet.
    P_EXCEPTION_DATE    DATE    DEFAULT NULL
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
    "OPEN_DATE"         DATE,
    "CLOSE_DATE"        DATE,
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
               e."OPEN_DATE"               AS "OPEN_DATE",
               e."CLOSE_DATE"              AS "CLOSE_DATE",
               COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
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
        -- Latest RULE_ASSIGN_OVERRIDE row per RULE_ID (written by Bulk
        -- Assign). Precedence: per-row EXCEPTION.ASSIGN_TO_ID wins over
        -- the bulk override, which wins over the RULE default. This
        -- ensures subsequent-run exceptions of a bulk-assigned rule
        -- pick up the new assignee before any per-row grid edit.
        LEFT JOIN (
            SELECT "RULE_ID", "ASSIGN_TO_ID"
            FROM (
                SELECT "RULE_ID", "ASSIGN_TO_ID",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID"
                           ORDER BY "CREATED_DATE" DESC,
                                    "RULE_ASSIGN_OVERRIDE_ID" DESC
                       ) AS rn
                FROM "RULE_ASSIGN_OVERRIDE"
            )
            WHERE rn = 1
        ) rao ON rao."RULE_ID" = r."RULE_ID"
        LEFT JOIN "DM_USER"                 du    ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
        WHERE e."EXCEPTION_DATE" = COALESCE(:P_EXCEPTION_DATE,
                                            TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())))
          AND (:P_ASSET_ID          IS NULL OR e."ASSET_ID" = :P_ASSET_ID)
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
-- Returns every distinct EXCEPTION_DATE the DQM Date dropdown should
-- offer, most recent first:
--   * the single MAX EXCEPTION_DATE from the live EXCEPTION table
--     (the "current" pick for the top of the dropdown)
--   * every distinct EXCEPTION_DATE from EXCEPTION_HIST
-- Union deduplicates when the live max also appears in HIST. No
-- CURRENT_DATE / UTC math: the labels are driven entirely by what's
-- actually in the two tables, so the frontend doesn't drift from
-- server state when local vs UTC disagree.
CREATE OR REPLACE PROCEDURE SP_GET_EXCEPTION_HIST_DATES()
RETURNS TABLE("EXCEPTION_DATE" DATE)
LANGUAGE SQL
AS
$$
DECLARE
    res RESULTSET;
BEGIN
    res := (
        SELECT d AS "EXCEPTION_DATE"
        FROM (
            SELECT MAX("EXCEPTION_DATE") AS d
              FROM "EXCEPTION"
             WHERE "EXCEPTION_DATE" IS NOT NULL
            UNION
            SELECT DISTINCT "EXCEPTION_DATE" AS d
              FROM "EXCEPTION_HIST"
             WHERE "EXCEPTION_DATE" IS NOT NULL
        ) x
        WHERE d IS NOT NULL
        ORDER BY d DESC
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
    "OPEN_DATE"         DATE,
    "CLOSE_DATE"        DATE,
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
               e."OPEN_DATE"               AS "OPEN_DATE",
               e."CLOSE_DATE"              AS "CLOSE_DATE",
               COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID") AS "ASSIGN_TO_ID",
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
        -- Latest per-rule bulk-assign override (see SP_GET_EXCEPTIONS
        -- for full precedence rationale). History mirrors the live
        -- grid so past-day views show the same effective assignee.
        LEFT JOIN (
            SELECT "RULE_ID", "ASSIGN_TO_ID"
            FROM (
                SELECT "RULE_ID", "ASSIGN_TO_ID",
                       ROW_NUMBER() OVER (
                           PARTITION BY "RULE_ID"
                           ORDER BY "CREATED_DATE" DESC,
                                    "RULE_ASSIGN_OVERRIDE_ID" DESC
                       ) AS rn
                FROM "RULE_ASSIGN_OVERRIDE"
            )
            WHERE rn = 1
        ) rao ON rao."RULE_ID" = r."RULE_ID"
        LEFT JOIN "DM_USER"                 du    ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
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
            -- Latest per-rule bulk-assign override (see SP_GET_EXCEPTIONS
            -- for full precedence rationale).
            LEFT JOIN (
                SELECT "RULE_ID", "ASSIGN_TO_ID"
                FROM (
                    SELECT "RULE_ID", "ASSIGN_TO_ID",
                           ROW_NUMBER() OVER (
                               PARTITION BY "RULE_ID"
                               ORDER BY "CREATED_DATE" DESC,
                                        "RULE_ASSIGN_OVERRIDE_ID" DESC
                           ) AS rn
                    FROM "RULE_ASSIGN_OVERRIDE"
                )
                WHERE rn = 1
            ) rao ON rao."RULE_ID" = r."RULE_ID"
            LEFT JOIN "DM_USER" du
              ON du."ID" = COALESCE(e."ASSIGN_TO_ID", rao."ASSIGN_TO_ID", r."ASSIGN_TO_ID")
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


-- End of dqm_init.sql
