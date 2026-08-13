-- Per-operator persistent settings, keyed by (DM_USER_ID,
-- RULE_GROUP_ID, RULE_CATALOG_ID). Column layouts are stored per
-- rule-group / rule-catalog scope so switching between Security
-- Master vs Bloomberg-Compare (or between catalogs inside a group)
-- restores the layout the operator arranged for that context.
-- COLUMN_ORDER itself is an opaque varchar (JSON / comma-joined
-- key list — encoding is a client-side contract, no schema change
-- needed when the client format evolves).
-- Postgres mirror of SNOWFLAKE/DM_USER_SETTINGS.sql.

DROP TABLE IF EXISTS public."DM_USER_SETTINGS";

CREATE TABLE public."DM_USER_SETTINGS" (
    "DM_USER_ID"       integer NOT NULL,
    "RULE_GROUP_ID"    integer,
    "RULE_CATALOG_ID"  integer,
    "COLUMN_ORDER"     varchar(5000)
);
