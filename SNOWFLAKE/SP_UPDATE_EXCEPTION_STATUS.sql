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
