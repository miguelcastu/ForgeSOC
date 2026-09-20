# Security policy

ForgeSOC is currently an educational project and has no supported production
release.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, or sensitive
telemetry. Contact the repository owner privately through the security reporting
channel configured on the repository host. Include affected version or commit,
impact, reproduction steps, and a suggested mitigation when possible.

## Data handling

Only synthetic telemetry belongs in this repository. Never commit API keys,
tokens, passwords, `.env` files, production logs, customer data, or personally
identifiable information. Revoke and rotate any secret committed accidentally;
deleting it from the latest commit is not sufficient because Git retains
history.

Database URLs contain credentials and must be supplied through environment
variables or an ignored `.env` file. Do not commit PostgreSQL dumps or copied
database volumes: even a development dump may contain telemetry or credentials.
The Compose defaults are local development credentials and must not be reused
in any shared or production environment.

The API uses PBKDF2 password hashing, signed eight-hour bearer sessions, and
role-based authorization. Set a unique, high-entropy `FORGESOC_SESSION_SECRET`;
changing it invalidates all existing sessions. The direct launcher and Compose
still bind to `127.0.0.1`. TLS termination, rate limiting, password recovery,
MFA, centralized identity, and production secret management are outside the
current educational scope, so do not expose the service directly to the
Internet. Imported telemetry must remain synthetic.
