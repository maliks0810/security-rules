-- SECURITY_CURRENT_VW: the current view of DIM_SECURITY. Postgres
-- mirror of SNOWFLAKE/SECURITY_CURRENT_VW.sql.
--
-- SELECT * as specified. Postgres, like Snowflake, expands the column
-- list when the view is CREATED rather than when it is queried, so a
-- column added to DIM_SECURITY later will NOT appear here until this
-- view is recreated. Re-run this file alongside any DIM_SECURITY
-- change.

CREATE OR REPLACE VIEW public."SECURITY_CURRENT_VW" AS
SELECT * FROM public."DIM_SECURITY";
