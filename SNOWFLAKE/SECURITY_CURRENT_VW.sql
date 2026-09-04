-- SECURITY_CURRENT_VW: the current view of DIM_SECURITY.
--
-- SELECT * as specified. Worth knowing that Snowflake resolves the
-- column list when the view is CREATED, not when it is queried, so a
-- column added to DIM_SECURITY later will NOT appear here until this
-- view is recreated. Re-run this file alongside any DIM_SECURITY
-- change.

CREATE OR REPLACE VIEW SECURITY_CURRENT_VW AS
SELECT * FROM DIM_SECURITY
go
