-- Sets EXCEPTION.ASSIGN_TO_ID for a single row keyed by EXCEPTION_ID,
-- resolving P_ASSIGN_TO against DM_USER.USER. Distinct from
-- SP_UPDATE_ASSIGN_TO (which touches every row for an ASSET_ID via the
-- Assets grid). Returns 1 on success.
--
-- ASSIGN_TO_ID is never written NULL. Empty / NULL P_ASSIGN_TO means
-- "unassigned", and unassigned is a real DM_USER row named 'Unassigned'
-- rather than an absent value, so the column always points at a user
-- and read paths never have to reason about NULL.
--
-- The one way that invariant can break: if DM_USER has no 'Unassigned'
-- row the lookup yields NULL and the old clear-to-NULL behaviour
-- returns. That row is required.

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
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "EXCEPTION_ID" = :P_EXCEPTION_ID;

    affected := SQLROWCOUNT;
    RETURN affected;
END;
$$;
