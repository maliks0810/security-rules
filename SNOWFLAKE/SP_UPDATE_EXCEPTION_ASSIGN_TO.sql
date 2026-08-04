-- Sets EXCEPTION.ASSIGN_TO_ID for a single row keyed by EXCEPTION_ID,
-- resolving P_ASSIGN_TO against DM_USER.USER. Empty/NULL clears the
-- assignment. Distinct from SP_UPDATE_ASSIGN_TO (which touches every
-- row for an ASSET_ID via the Assets grid). Returns 1 on success.

CREATE OR REPLACE PROCEDURE SP_UPDATE_EXCEPTION_ASSIGN_TO(
    P_EXCEPTION_ID NUMBER,
    P_ASSIGN_TO    VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
    user_id  NUMBER := NULL;
BEGIN
    IF (:P_ASSIGN_TO IS NOT NULL AND :P_ASSIGN_TO <> '') THEN
        SELECT "ID" INTO :user_id
        FROM "DM_USER"
        WHERE "USER" = :P_ASSIGN_TO
        LIMIT 1;
    END IF;

    UPDATE "EXCEPTION"
       SET "ASSIGN_TO_ID"  = :user_id,
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
