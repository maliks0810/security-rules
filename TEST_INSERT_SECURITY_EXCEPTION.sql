-- Snowflake test invocation of INSERT_SECURITY_EXCEPTION.
-- Inserts a row for rule 137 against asset 38384LJ83.

CALL INSERT_SECURITY_EXCEPTION(
    900300,                          -- SECURITY_EXCEPTION_ID
    137,                             -- RULE_ID
    CURRENT_TIMESTAMP(),             -- RUN_DATE
    CURRENT_TIMESTAMP(),             -- RUN_START
    NULL,                            -- RUN_END
    1,                               -- RESULT_TYPE_ID
    1,                               -- EXCEPTION_STATUS_ID
    1,                               -- SEVERITY_TYPE_ID
    1,                               -- PROCESS_TYPE_ID
    1,                               -- CATEGORY_TYPE_ID
    'demo',                          -- ASSIGN_TO
    NULL,                            -- ASSIGN_TO_DATE
    NULL,                            -- RESOLVE_DATE
    NULL,                            -- BUS_TERM_SOURCE_ID
    'Cusip Unaudited',               -- ISSUE_DESCRIPTION
    NULL,                            -- SOURCE_SYSTEM_CODE
    CURRENT_TIMESTAMP(),             -- CREATED_DATE
    'demo',                          -- CREATED_BY
    'demo',                          -- MODIFIED_BY
    CURRENT_TIMESTAMP(),             -- MODIFIED_DATE
    1,                               -- EXCEPTION_SOURCE_ID
    NULL,                            -- EXCEPTION_TYPE_ID
    NULL,                            -- DQM_APP_ID
    NULL,                            -- ASSET_TYPE_ID
    NULL,                            -- ASSET
    NULL,                            -- CUSIP_TYPE_CODE
    'demo',                          -- ASSIGNED_BY
    NULL,                            -- COMMENTS
    '38384LJ83'                      -- ALADDIN_ID
);
