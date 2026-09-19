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

The Sprint 5 API has no authentication or authorization. Its direct launcher
binds to `127.0.0.1` deliberately. Do not expose port 8000 to an untrusted
network, and do not deploy the Compose configuration as a public service.
Imported JSONL is limited and validated, but only synthetic telemetry belongs
in this educational environment.
