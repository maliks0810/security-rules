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
    ('Naomi Lynch'),
    ('Sumit Malik'),
    ('Ethan Abraham'),
    ('Mukesh Verma'),
    ('Shrenik Doshi'),
    ('Mark Segura'),
    ('Ken Desouza'),
    ('Manish Ghayalod'),
    ('Ari Novosyolok'),
    ('Greg Killeen'),
    ('Jay Nolledo'),
    ('Bruce Pople'),
    ('Melissa Stolfi'),
    ('Sidharth Joshi'),
    ('Prasanna Ramamoorthy');

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
-- IT_SUPPORT operators inherit every DM_ADMIN gate on the frontend
-- (Bulk Assign/Status buttons visible, per-row Assign To editable)
-- but are deliberately hidden from the Assign To dropdown itself —
-- support staff should be able to fix an assignment, not be a valid
-- assignment target. SP_GET_DM_USERS filters ROLE='IT_SUPPORT' out
-- of the dropdown feed for that reason.
UPDATE DM_USER SET EMAIL = 'Sumit.Malik@tcw.com',    ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Sumit Malik';
UPDATE DM_USER SET EMAIL = 'Ethan.Abraham@tcw.com',  ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Ethan Abraham';
UPDATE DM_USER SET EMAIL = 'Mukesh.Verma@tcw.com',   ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Mukesh Verma';
UPDATE DM_USER SET EMAIL = 'Shrenik.Doshi@tcw.com',  ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Shrenik Doshi';
UPDATE DM_USER SET EMAIL = 'Mark.Segura@tcw.com',    ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Mark Segura';
UPDATE DM_USER SET EMAIL = 'Ken.Desouza@tcw.com',    ROLE = 'IT_SUPPORT'
 WHERE "USER" = 'Ken Desouza';

-- IT_USER: same UI privileges as IT_SUPPORT (Bulk Assign/Status
-- buttons visible, per-row Assign To editable), also hidden from
-- the Assign To dropdown source (SP_GET_DM_USERS filters both
-- IT_SUPPORT and IT_USER out of the dropdown feed). Distinct role
-- name reserved so future policy can diverge without touching the
-- DM_ADMIN row set. Greg Killeen's email intentionally uses the
-- long "Gregory" form — the rest follow First.Last@tcw.com.
UPDATE DM_USER SET EMAIL = 'Manish.Ghayalod@tcw.com',      ROLE = 'IT_USER'
 WHERE "USER" = 'Manish Ghayalod';
UPDATE DM_USER SET EMAIL = 'Ari.Novosyolok@tcw.com',       ROLE = 'IT_USER'
 WHERE "USER" = 'Ari Novosyolok';
UPDATE DM_USER SET EMAIL = 'Gregory.Killeen@tcw.com',      ROLE = 'IT_USER'
 WHERE "USER" = 'Greg Killeen';
UPDATE DM_USER SET EMAIL = 'Jay.Nolledo@tcw.com',          ROLE = 'IT_USER'
 WHERE "USER" = 'Jay Nolledo';
UPDATE DM_USER SET EMAIL = 'Bruce.Pople@tcw.com',          ROLE = 'IT_USER'
 WHERE "USER" = 'Bruce Pople';
UPDATE DM_USER SET EMAIL = 'Melissa.Stolfi@tcw.com',       ROLE = 'IT_USER'
 WHERE "USER" = 'Melissa Stolfi';
UPDATE DM_USER SET EMAIL = 'Sidharth.Joshi@tcw.com',       ROLE = 'IT_USER'
 WHERE "USER" = 'Sidharth Joshi';
UPDATE DM_USER SET EMAIL = 'Prasanna.Ramamoorthy@tcw.com', ROLE = 'IT_USER'
 WHERE "USER" = 'Prasanna Ramamoorthy';

-- Every named user other than the DM_ADMINs, IT_SUPPORT / IT_USER
-- operators, and Unassigned (the placeholder) gets the default
-- DM_USER role.
UPDATE DM_USER SET ROLE = 'DM_USER'
 WHERE "USER" NOT IN (
    'Joann Banks', 'Naomi Lynch',
    'Sumit Malik', 'Ethan Abraham', 'Mukesh Verma',
    'Shrenik Doshi', 'Mark Segura', 'Ken Desouza',
    'Manish Ghayalod', 'Ari Novosyolok', 'Greg Killeen',
    'Jay Nolledo', 'Bruce Pople', 'Melissa Stolfi',
    'Sidharth Joshi', 'Prasanna Ramamoorthy',
    'Unassigned'
 );
