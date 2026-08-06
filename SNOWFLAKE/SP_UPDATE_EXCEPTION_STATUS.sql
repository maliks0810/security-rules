CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_STATUS(
    P_EXCEPTION_ID NUMBER,
    P_STATUS_NAME  VARCHAR
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
           -- Only 'Suppress' keeps a SUPPRESS_DATE. Moving off Suppress
           -- (to New / Accept / Override / Complete / …) clears the
           -- date so the grid never shows a stale suppression next to
           -- a non-Suppress row. Parity with SP_UPDATE_BULK_STATUS.
           "SUPPRESS_DATE" = CASE
                                 WHEN :P_STATUS_NAME = 'Suppress'
                                     THEN "SUPPRESS_DATE"
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
                                 -- Transition back to 'New' reopens the
                                 -- row; the historical close date is no
                                 -- longer valid and gets cleared.
                                 WHEN :P_STATUS_NAME = 'New'
                                     THEN NULL
                                 ELSE "CLOSE_DATE"
                             END,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID
       AND EXISTS (
           SELECT 1 FROM "EXCEPTION_STATUS" WHERE "NAME" = :P_STATUS_NAME
       )
       AND NOT (:P_STATUS_NAME = 'Suppress' AND "SUPPRESS_DATE" IS NULL)
       -- Any transition away from 'New' (Accept / Override / Hold /
       -- Suppress / Research / Challenge / …) must carry an operator
       -- comment so the audit trail on a triaged row is never empty.
       -- Reject on blank COMMENTS. Parity with SP_UPDATE_BULK_STATUS.
       AND NOT (:P_STATUS_NAME <> 'New'
                AND ("COMMENTS" IS NULL OR "COMMENTS" = ''));
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
