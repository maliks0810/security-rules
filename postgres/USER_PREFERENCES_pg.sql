-- Per-operator persistent UI preferences, keyed by
-- (DM_USER_ID, RULE_GROUP_ID, RULE_CATALOG_ID). Today the only
-- persisted preference is COLUMN_ORDER, an opaque varchar the
-- client encodes as JSON (an ordered array of grid column names).
-- RULE_CATALOG_ID is nullable — when the LHS tree is at the group
-- root (no catalog drilled into) the row is scoped to the whole
-- group.
-- Postgres mirror of SNOWFLAKE/USER_PREFERENCES.sql.

DROP TABLE IF EXISTS public."USER_PREFERENCES";

CREATE TABLE public."USER_PREFERENCES" (
    "DM_USER_ID"       integer,
    "RULE_GROUP_ID"    integer,
    "RULE_CATALOG_ID"  integer,
    "COLUMN_ORDER"     varchar(5000),
    "CREATED_DATE"     timestamp,
    "CREATED_BY"       varchar(100),
    "MODIFIED_DATE"    timestamp,
    "MODIFIED_BY"      varchar(100)
);
