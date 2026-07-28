# Security policy

RekaSerdoba is research software and has not completed an independent cryptographic audit.

## Reporting a vulnerability

Please do not open a public issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting flow:

<https://github.com/kristexIO/RekaSerdoba/security/advisories/new>

Include:

- affected commit or version;
- carrier and operating system;
- minimal reproduction;
- expected security impact;
- whether the issue is already being exploited.

Do not include production private keys, device bundles, access tokens, IP packet captures containing personal data, or server credentials.

## Supported versions

Only the current `main` branch is supported during the research phase.

## Security boundaries

- Standard primitives do not imply that the complete protocol has been audited.
- Gate credentials are admission capabilities, not user authentication.
- Personalized bundles must be distributed out of band and stored as secrets.
- Reference deployment files are examples and require local review before production use.
