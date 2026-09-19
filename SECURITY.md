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
