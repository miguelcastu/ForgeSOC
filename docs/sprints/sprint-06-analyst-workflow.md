# Sprint 6: Authenticated analyst workflow

## Goal

Turn the read-oriented console into an accountable investigation workspace in
which users can own, document, group, and resolve findings.

## Delivered

- One-time administrator bootstrap, login, signed sessions, and logout.
- Admin, analyst, and viewer roles enforced by the API and reflected in the UI.
- Alert states (`open`, `investigating`, `closed`), assignee, and disposition.
- Timestamped investigation notes with authorship.
- Cases that group one or more alerts with priority, owner, and state.
- Audit records for bootstrap, user creation, workflow updates, notes, and cases.
- Administration and case-management screens in the browser.
- Alembic migration and PostgreSQL integration coverage.

## Typical workflow

1. Create the first administrator on the login screen.
2. Add analyst and viewer accounts in Administration.
3. Generate telemetry and run detections.
4. Open an alert, assign it, set it to investigating, and add notes.
5. Group related alerts into a case.
6. Close the alert with a true-positive, false-positive, or benign disposition.
7. Review the audit trail for accountability.

## Security boundary

This sprint makes local collaboration accountable, but does not make ForgeSOC
an Internet-facing production service. The deployment remains localhost-only
and needs a unique session secret. MFA, federation, TLS, recovery, rate limits,
and session revocation are future production-hardening concerns.
