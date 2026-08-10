-- =============================================================================
-- INIT_DM_USERS.sql
--
-- Standalone seed script for the DM_USER table. Mirrors the DM_USER
-- block in dqm_seed_data.sql so operators can re-run just the user
-- seed without touching the rest of the seed data.
--
-- Prerequisite: DM_USER table already exists (created by dqm_init.sql).
--
-- Idempotent guidance: the INSERT below assumes an empty DM_USER.
-- On a re-run against a populated table you'll get duplicate-name
-- rows. If you're topping up an existing environment, run only the
-- UPDATE statements — or delete the affected rows first.
-- =============================================================================

-- DM_USER ---------------------------------------------------------------------
INSERT INTO DM_USER ("USER") VALUES
    ('Unassigned'),
    ('Paul Cohen'),
    ('Jake Rigney'),
    ('Anush Safaryan'),
    ('Jimmy Fu'),
    ('Natasha Cabrera'),
    ('Joann Banks'),
    ('Naomi Lynch');

-- Backfill EMAIL + ROLE for the seeded users. Kept as UPDATE-by-name
-- so the statements stay valid even if the surrogate ID sequence has
-- shifted (fresh env vs re-run). "Unassigned" is intentionally left
-- with NULL email + NULL role — it's the placeholder for "no
-- assignee", not a real user.
UPDATE DM_USER SET EMAIL = 'Paul.Cohen@tcw.com'      WHERE "USER" = 'Paul Cohen';
UPDATE DM_USER SET EMAIL = 'Jake.Rigney@tcw.com'     WHERE "USER" = 'Jake Rigney';
UPDATE DM_USER SET EMAIL = 'Anush.Safaryan@tcw.com'  WHERE "USER" = 'Anush Safaryan';
UPDATE DM_USER SET EMAIL = 'Jimmy.Fu@tcw.com'        WHERE "USER" = 'Jimmy Fu';
UPDATE DM_USER SET EMAIL = 'Natasha.Cabrera@tcw.com' WHERE "USER" = 'Natasha Cabrera';
UPDATE DM_USER SET EMAIL = 'Joann.Banks@tcw.com', ROLE = 'DM_ADMIN'
 WHERE "USER" = 'Joann Banks';
UPDATE DM_USER SET EMAIL = 'Naomi.Lynch@tcw.com', ROLE = 'DM_ADMIN'
 WHERE "USER" = 'Naomi Lynch';

-- Every named user other than the DM_ADMINs and Unassigned (the
-- placeholder) gets the default DM_USER role.
UPDATE DM_USER SET ROLE = 'DM_USER'
 WHERE "USER" NOT IN ('Joann Banks', 'Naomi Lynch', 'Unassigned');
