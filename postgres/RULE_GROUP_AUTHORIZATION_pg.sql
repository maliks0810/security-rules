-- One row per RULE_GROUP, holding the list of operators (or roles)
-- authorized to see / act on that group. ACCESS_LIST is a free-form
-- VARCHAR so callers can encode whatever list format the frontend
-- needs (comma-separated emails is the current convention — see
-- SP_GET_RULE_GROUPS_FOR_USER for the match semantics).
-- Postgres mirror of SNOWFLAKE/RULE_GROUP_AUTHORIZATION.sql.

CREATE TABLE IF NOT EXISTS public."RULE_GROUP_AUTHORIZATION" (
    "RULE_GROUP_ID" integer,
    "ACCESS_LIST"   varchar(5000),
    "CREATED_DATE"  timestamp,
    "CREATED_BY"    varchar(100)
);
