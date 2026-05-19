-- Sends a NOTIFY on the 'security_exception_inserted' channel after every
-- INSERT into public."SECURITY_EXCEPTION", regardless of who issued the
-- INSERT (Go service, psql, pgAdmin, external job). The payload is small on
-- purpose; downstream consumers refetch the row(s) they need.

CREATE OR REPLACE FUNCTION public."notify_security_exception_inserted"()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Payload is "<security_exception_id>|<asset_id>|<rule_id>" rather than JSON
    -- because some lib/pq + payload-shape combinations don't deliver braces+quotes
    -- reliably from a trigger context.
    PERFORM pg_notify(
        'security_exception_inserted',
        NEW."SECURITY_EXCEPTION_ID" || '|' ||
        COALESCE(NEW."ASSET_ID", '') || '|' ||
        COALESCE(NEW."RULE_ID"::text, '')
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_exception_inserted_notify
    ON public."SECURITY_EXCEPTION";

CREATE TRIGGER security_exception_inserted_notify
    AFTER INSERT ON public."SECURITY_EXCEPTION"
    FOR EACH ROW
    EXECUTE FUNCTION public."notify_security_exception_inserted"();
