-- Sets EXCEPTION.ASSIGN_TO_ID for every row of an ASSET_ID, resolving
-- P_ASSIGN_TO against DM_USER.USER. Assets-grid counterpart to
-- SP_UPDATE_EXCEPTION_ASSIGN_TO.
--
-- ASSIGN_TO_ID is never written NULL. Empty / NULL P_ASSIGN_TO means
-- "unassigned", and unassigned is a real DM_USER row named 'Unassigned'
-- rather than an absent value. DM_USER must carry that row, or the
-- lookup yields NULL and the old clear-to-NULL behaviour returns.
CREATE OR REPLACE PROCEDURE SP_UPDATE_ASSIGN_TO(
    P_ASSET_ID  VARCHAR,
    P_ASSIGN_TO VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
    user_id  NUMBER := NULL;
BEGIN
    -- Empty resolves to the 'Unassigned' user rather than to NULL.
    SELECT "ID" INTO :user_id
    FROM "DM_USER"
    WHERE "USER" = CASE
                       WHEN :P_ASSIGN_TO IS NULL OR :P_ASSIGN_TO = ''
                           THEN 'Unassigned'
                       ELSE :P_ASSIGN_TO
                   END
    LIMIT 1;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = CURRENT_TIMESTAMP()::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "ASSET_ID" = :P_ASSET_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
