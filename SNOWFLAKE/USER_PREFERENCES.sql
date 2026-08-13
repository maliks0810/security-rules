-- USER_PREFERENCES ------------------------------------------------------------
-- Per-operator persistent UI preferences, keyed by
-- (DM_USER_ID, RULE_GROUP_ID, RULE_CATALOG_ID). Today the only
-- persisted preference is COLUMN_ORDER, an opaque VARCHAR the
-- client encodes as JSON (an ordered array of grid column names).
-- The scope tuple lets an operator arrange the columns differently
-- per group / per catalog, and RULE_CATALOG_ID is intentionally
-- nullable — when the LHS tree is at the group root (no catalog
-- drilled into) the row is scoped to the whole group.
--
-- Snowflake has no true unique constraint, so (DM_USER_ID,
-- RULE_GROUP_ID, RULE_CATALOG_ID) uniqueness is enforced by the
-- upsert path in SP_UPDATE_USER_PREFERENCES rather than by DDL.
CREATE OR REPLACE TABLE USER_PREFERENCES (
    DM_USER_ID       NUMBER(38,0),
    RULE_GROUP_ID    NUMBER(38,0),
    RULE_CATALOG_ID  NUMBER(38,0),
    COLUMN_ORDER     VARCHAR(5000),
    CREATED_DATE     TIMESTAMP_NTZ(9),
    CREATED_BY       VARCHAR(100),
    MODIFIED_DATE    TIMESTAMP_NTZ(9),
    MODIFIED_BY      VARCHAR(100)
);
