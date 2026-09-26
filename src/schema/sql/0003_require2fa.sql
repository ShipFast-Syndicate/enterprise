-- Alpha Bros enterprise layer — migration 0003 (data only, no schema change).
--
-- `org_policy.require_2fa` is enforced from 1.1.0 on; 1.0.x only reported it
-- on `/get-session`. A session minted under 1.0.x for a member of an org that
-- already required a second factor was therefore never judged against it —
-- yet it may postdate the org's `updated_at`, which is the instant the
-- policy plugin treats as the requirement's onset: a session created
-- strictly after it is taken to have been judged when it was created
-- (`src/server/policy/enforcement.ts`, `twoFactorStanding`). Moving the onset
-- of every requiring org to the moment of the upgrade makes every session
-- that exists at that moment an unjudged one: a member who cannot enrol (no
-- password) signs in again once, a password member who has not enrolled is
-- confined to enrolment, an enrolled member is unaffected.
--
-- The new value keeps the column's unit — whole seconds, milliseconds, or an
-- ISO-8601 string — and is rounded **up** (to the next second, or the next
-- millisecond), so no session created before the statement ran can read as
-- later than it. Only rows with `require_2fa = 1` are touched (production had
-- none on 2026-09-26, where this is a no-op).
--
-- Run it once, as part of the upgrade: through `ab-enterprise migrate --out`
-- (a drizzle journal applies it exactly once) or `applyMigration()`. Running
-- it again later is safe but not free — it moves the onset again, so members
-- of requiring orgs who hold no password and are not enrolled sign in once
-- more.
UPDATE org_policy
SET updated_at = CASE
  WHEN typeof(updated_at) = 'text' AND updated_at GLOB '*[^0-9.]*'
    THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+0.001 seconds')
  WHEN CAST(updated_at AS REAL) < 100000000000
    THEN CAST(strftime('%s', 'now') AS INTEGER) + 1
  ELSE CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER) + 1
END
WHERE require_2fa = 1;
