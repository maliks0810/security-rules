CREATE OR REPLACE PROCEDURE SP_EXPIRE_SUPPRESS_DATES()
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    affected NUMBER := 0;
BEGIN
    UPDATE "EXCEPTION"
       SET "STATUS_ID"     = 1,
           "SUPPRESS_DATE" = NULL,
           -- OPEN_DATE is write-once. A row coming back from Suppress
           -- or Hold was surfaced long before this sweep, so releasing
           -- it must NOT reset its age - the grid would show every
           -- released row as opened today. COALESCE only fills a gap.
           "OPEN_DATE"     = COALESCE("OPEN_DATE", TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()))),
           "MODIFIED_DATE" = CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP())::TIMESTAMP_NTZ,
           "MODIFIED_BY"   = 'system'
     WHERE "SUPPRESS_DATE" IS NOT NULL
       AND "SUPPRESS_DATE" < TO_DATE(CONVERT_TIMEZONE('UTC', CURRENT_TIMESTAMP()));
    affected := SQLROWCOUNT;

    -- Hold release used to live here as a second pass that counted 2
    -- business days forward from OPEN_DATE, on the assumption that
    -- applying a Hold stamped OPEN_DATE with the day it was applied.
    --
    -- OPEN_DATE is now write-once - it means "the day this exception
    -- was first surfaced" and nothing else - so that assumption no
    -- longer holds. Left in place it would have read the original
    -- surfacing date, found it weeks past, and released every held row
    -- on the very next sweep.
    --
    -- Nothing is lost by removing it. Applying a Hold also sets
    -- SUPPRESS_DATE to the same 2 business days out (see
    -- SP_UPDATE_EXCEPTION_STATUS / SP_UPDATE_BULK_STATUS), so the
    -- SUPPRESS_DATE branch above releases exactly the same rows on
    -- exactly the same day: a Friday hold runs through Tuesday and
    -- returns to New on Wednesday. The old pass was explicitly
    -- documented as agreeing with that branch by construction; now it
    -- is simply the one that does the work.

    RETURN affected;
END;
$$;
