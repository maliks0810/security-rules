-- Per-rule assignee override written by the Bulk Assign flow when the
-- caller does NOT tick "Is Permanent". Latest row per RULE_ID wins in
-- the grid: SP_GET_EXCEPTIONS / SP_GET_EXCEPTIONS_HIST / SP_GET_ASSETS
-- prefer this ASSIGN_TO_ID over RULE.ASSIGN_TO_ID for rows where
-- EXCEPTION.ASSIGN_TO_ID is NULL (per-row grid reassignment still wins
-- over the override). When Bulk Assign is submitted with Is Permanent
-- ticked, SP_UPDATE_BULK_ASSIGN writes RULE.ASSIGN_TO_ID directly and
-- skips this table entirely. ASSIGN_TO_UNTIL_DATE is recorded but not
-- currently used to expire overrides — metadata for future time-boxed
-- assignments.

CREATE OR REPLACE TABLE RULE_ASSIGN_OVERRIDE (
    RULE_ASSIGN_OVERRIDE_ID NUMBER IDENTITY(1,1) PRIMARY KEY,
    RULE_ID                 INT NOT NULL,
    ASSIGN_TO_ID            INT NOT NULL,
    ASSIGN_TO_UNTIL_DATE    DATE,
    CREATED_BY              VARCHAR(100),
    CREATED_DATE            TIMESTAMP_NTZ(9)
);
