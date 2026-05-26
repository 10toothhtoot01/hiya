# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: dheerajgujarathi@gmail.com (or open a private GitHub security advisory)

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

You will receive a response within 72 hours. If confirmed, a fix will be released within 14 days for critical issues.

## Scope

In scope: daemon D-Bus interface, PAM module, FIDO2 authenticator, enrollment storage, TPM integration, crypto primitives.

Out of scope: libfprint itself, underlying kernel drivers, third-party dependencies.
