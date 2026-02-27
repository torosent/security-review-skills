# Compliance Frameworks Mapping

## SOC 2 Trust Service Criteria → Security Checks

| Control | Category | Automated Check |
|---------|----------|-----------------|
| CC6.1 | Logical Access | Auth on all endpoints, RBAC implemented |
| CC6.2 | Credentials | No hardcoded secrets, MFA supported |
| CC6.3 | Encryption | TLS 1.2+, data encrypted at rest, no weak ciphers |
| CC6.6 | System Boundaries | Network segmentation, firewall rules, no 0.0.0.0/0 |
| CC6.7 | Data Transmission | HTTPS enforced, no HTTP for sensitive data |
| CC6.8 | Malicious Software | Dependency scanning, no known CVEs |
| CC7.1 | Monitoring | Logging enabled, security events captured |
| CC7.2 | Detection | Alerting configured, error monitoring |
| CC8.1 | Change Mgmt | Code review required, CI/CD secured |

## HIPAA Security Rule → Security Checks

| Section | Requirement | Automated Check |
|---------|-------------|----------------|
| §164.312(a)(1) | Access Control | Auth on PHI endpoints, session management |
| §164.312(a)(2)(iv) | Encryption | AES-256 for PHI at rest |
| §164.312(c)(1) | Integrity | Input validation, checksums on PHI |
| §164.312(d) | Authentication | Strong passwords, MFA on PHI access |
| §164.312(e)(1) | Transmission Security | TLS 1.2+ for all PHI transmission |
| §164.308(a)(5)(ii)(C) | Log-in Monitoring | Failed login logging and alerting |
| §164.312(b) | Audit Controls | Audit logs for PHI access/modification |

## PCI-DSS v4.0 → Security Checks

| Req | Description | Automated Check |
|-----|-------------|----------------|
| 2.2.7 | No unnecessary services | Minimal container images, no debug in prod |
| 3.5 | Protect stored PAN | grep for credit card patterns, encryption checks |
| 4.2 | Encrypt transmission | TLS enforcement, certificate validation |
| 6.2.4 | Prevent common vulns | OWASP Top 10 pass, injection checks |
| 6.3.1 | Known vulnerabilities | Dependency audit pass, no critical CVEs |
| 6.4.1 | Public-facing app protection | WAF/CSP headers, input validation |
| 8.3.6 | Password complexity | Password policy enforcement in code |
| 8.6.2 | No hardcoded creds | Secrets detection pass |
| 10.2 | Audit trail | Logging implementation check |

## Credit Card Pattern Detection (PCI)

```
\b[3-6]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b    # Visa, MC, Discover
\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b                  # Amex
```

Flag any storage/logging of card numbers without tokenization.

## Mapping Findings to Compliance

When reporting findings, add `Compliance:` line listing affected frameworks:
- SQL Injection → PCI 6.2.4, SOC2 CC6.1, HIPAA §164.312(c)(1)
- Hardcoded secrets → PCI 8.6.2, SOC2 CC6.2
- Missing TLS → PCI 4.2, SOC2 CC6.7, HIPAA §164.312(e)(1)
- No audit logging → PCI 10.2, SOC2 CC7.1, HIPAA §164.312(b)
