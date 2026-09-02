CREATE OR REPLACE PROCEDURE SP_EXPIRE_SUPPRESS_DATES()
RETURNS NUMBER
LANGUAGE SQL
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = 1,
           "SUPPRESS_DATE" = NULL,
           -- Every row this touches transitions back to STATUS_ID=1
           -- (New), so OPEN_DATE ratchets to today.
           "OPEN_DATE"     = TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "SUPPRESS_DATE" IS NOT NULL
       AND "SUPPRESS_DATE" < TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected := SQLROWCOUNT;

    -- Hold release. A Hold stamps OPEN_DATE = the day it was applied
    -- and SUPPRESS_DATE = 2 business days on from it, so this counts
    -- the same 2 business days forward from OPEN_DATE and releases the
    -- row once that day has passed: a Friday hold runs through Tuesday
    -- and returns to New on Wednesday.
    --
    -- Weekends only, no holiday calendar (none exists in this schema).
    -- Offsets by ISO weekday: Mon/Tue/Wed +2, Thu/Fri +4 (skipping the
    -- weekend), Sat +3, Sun +2.
    --
    -- Agrees with the SUPPRESS_DATE branch above by construction, since
    -- both derive from the same day and the same offsets - that branch
    -- would already catch these rows. Kept explicit so Hold's lifecycle
    -- is readable on its own rather than an emergent property of the
    -- date it happens to carry.
    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = 1,
           "SUPPRESS_DATE" = NULL,
           "OPEN_DATE"     = TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "STATUS_ID" = 7
       AND "OPEN_DATE" IS NOT NULL
       AND TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())) >
           DATEADD(
               day,
               CASE DAYOFWEEKISO("OPEN_DATE")
                   WHEN 4 THEN 4
                   WHEN 5 THEN 4
                   WHEN 6 THEN 3
                   ELSE 2
               END,
               "OPEN_DATE"
           );
    affected := affected + SQLROWCOUNT;

    RETURN affected;
END;
$$;
