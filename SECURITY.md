# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| latest (main) | ✅ |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Aavekshak is a security tool — responsible disclosure is especially important here.

To report a vulnerability, email **kunal.kumar.dey@sap.com** with:

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fix (optional)

You will receive a response within **48 hours** acknowledging receipt. We aim to release a fix within **7 days** for critical issues.

We will credit you in the release notes unless you prefer to remain anonymous.

## Scope

The following are in scope:

- Authentication or authorisation bypasses in the API
- Remote code execution via crafted alert payloads
- Data exposure through the API or agent ledger
- Dependency vulnerabilities with a direct exploit path

The following are **out of scope**:

- Vulnerabilities in Ollama, PostgreSQL, or Redis (report to their maintainers)
- Issues requiring physical access to the host machine
- Denial of service against a self-hosted instance you control
