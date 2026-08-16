-- =============================================================================
-- INIT_DM_USERS.sql
--
-- Standalone seed script for the DM_USER table. Single INSERT with all
-- three data columns (USER, EMAIL, ROLE) so a fresh environment gets
-- the correct rows in one shot — no follow-up UPDATE sweep needed.
--
-- Prerequisite: DM_USER table already exists (created by dqm_init.sql).
--
-- Idempotence: not idempotent — the INSERT assumes an empty DM_USER.
-- Re-running against a populated table produces duplicate names.
-- To top up an existing environment, edit or wrap the INSERT with a
-- WHERE-NOT-EXISTS guard.
--
-- Role semantics:
--   DM_ADMIN   — unlocks Bulk Assign / Bulk Status buttons and per-row
--                Assign To editability. Selectable as an assignment
--                target.
--   IT_SUPPORT — same UI privileges as DM_ADMIN, but excluded from the
--                Assign To dropdown source (SP_GET_DM_USERS filters
--                ROLE IN ('IT_SUPPORT','IT_USER') out). Support staff
--                can fix an assignment, not be one.
--   IT_USER    — mirrors IT_SUPPORT today. Distinct role name reserved
--                so future policy can diverge without a schema change.
--   DM_USER    — least-privileged operator (default target-selectable).
--   NULL       — reserved for the "Unassigned" placeholder row.
--
-- Greg Killeen's email intentionally uses the long "Gregory" form —
-- every other row follows First.Last@tcw.com.
-- =============================================================================

INSERT INTO DM_USER ("USER", "EMAIL", "ROLE") VALUES
    ('Unassigned',            NULL,                              NULL),
    ('Paul Cohen',             'Paul.Cohen@tcw.com',              'DM_USER'),
    ('Jake Rigney',            'Jake.Rigney@tcw.com',             'DM_USER'),
    ('Anush Safaryan',         'Anush.Safaryan@tcw.com',          'DM_USER'),
    ('Jimmy Fu',               'Jimmy.Fu@tcw.com',                'DM_USER'),
    ('Natasha Cabrera',        'Natasha.Cabrera@tcw.com',         'DM_USER'),
    ('Joann Banks',            'Joann.Banks@tcw.com',             'DM_ADMIN'),
    ('Naomi Lynch',            'Naomi.Lynch@tcw.com',             'DM_ADMIN'),
    ('Sumit Malik',            'Sumit.Malik@tcw.com',             'IT_SUPPORT'),
    ('Ethan Abraham',          'Ethan.Abraham@tcw.com',           'IT_SUPPORT'),
    ('Mukesh Verma',           'Mukesh.Verma@tcw.com',            'IT_SUPPORT'),
    ('Shrenik Doshi',          'Shrenik.Doshi@tcw.com',           'IT_SUPPORT'),
    ('Mark Segura',            'Mark.Segura@tcw.com',             'IT_SUPPORT'),
    ('Ken Desouza',            'Ken.Desouza@tcw.com',             'IT_SUPPORT'),
    ('Manish Ghayalod',        'Manish.Ghayalod@tcw.com',         'IT_USER'),
    ('Ari Novosyolok',         'Ari.Novosyolok@tcw.com',          'IT_USER'),
    ('Greg Killeen',           'Gregory.Killeen@tcw.com',         'IT_USER'),
    ('Jay Nolledo',            'Jay.Nolledo@tcw.com',             'IT_USER'),
    ('Bruce Pople',            'Bruce.Pople@tcw.com',             'IT_USER'),
    ('Melissa Stolfi',         'Melissa.Stolfi@tcw.com',          'IT_USER'),
    ('Sidharth Joshi',         'Sidharth.Joshi@tcw.com',          'IT_USER'),
    ('Prasanna Ramamoorthy',   'Prasanna.Ramamoorthy@tcw.com',    'IT_USER');
