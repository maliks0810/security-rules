-- RULE_GROUP_AUTHORIZATION ----------------------------------------------------
-- One row per RULE_GROUP, holding the list of operators (or roles)
-- authorized to see / act on that group. ACCESS_LIST is a free-form
-- VARCHAR so callers can encode whatever list format the frontend
-- needs (comma-separated names, JSON, etc.) without a schema change.
CREATE OR REPLACE TABLE RULE_GROUP_AUTHORIZATION (
    RULE_GROUP_ID  NUMBER(38,0),
    ACCESS_LIST    VARCHAR(5000),
    CREATED_DATE   TIMESTAMP_NTZ(9),
    CREATED_BY     VARCHAR(100)
);
