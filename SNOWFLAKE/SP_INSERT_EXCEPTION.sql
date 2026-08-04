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
