# Severity Scoring Guide

## Classification Criteria

### 🔴 Critical (CVSS 9.0-10.0)
- Remote Code Execution (RCE) — attacker executes arbitrary code
- Hardcoded credentials for production systems
- SQL injection allowing data exfiltration/modification
- Authentication bypass granting admin access
- Unencrypted secrets in source control
- Open security groups (0.0.0.0/0) on sensitive ports
- Container running as root with host mounts

**Action**: Must fix before merge/deploy. Block deployment.

### 🟠 High (CVSS 7.0-8.9)
- Stored/Reflected XSS in authenticated areas
- SSRF with internal network access
- Insecure deserialization of user input
- Missing authentication on sensitive endpoints
- Path traversal with file read/write
- Privileged containers without justification
- Known CVE with active exploit in dependency

**Action**: Fix before production deployment. May merge with tracking issue.

### 🟡 Medium (CVSS 4.0-6.9)
- CSRF on state-changing operations
- Missing rate limiting on auth endpoints
- Information disclosure (stack traces, versions)
- Weak cryptographic algorithms (SHA1, MD5 for security)
- Missing security headers (CSP, HSTS)
- Outdated TLS version (1.0/1.1)
- Missing resource limits on containers

**Action**: Fix within current sprint. Track in backlog.

### 🟢 Low (CVSS 0.1-3.9)
- Missing `HttpOnly` flag on non-sensitive cookies
- Verbose error messages in non-production
- Missing `rel="noopener"` on external links
- Insecure randomness for non-security purposes
- Default namespace in Kubernetes
- Missing healthcheck in Dockerfile

**Action**: Fix when convenient. Add to tech debt backlog.

### ℹ️ Info (CVSS 0.0)
- Outdated dependency without known CVE
- Missing but non-critical security header
- Code quality suggestion with security benefit
- Best practice recommendation

**Action**: Optional improvement. No urgency.

## Scoring Decision Matrix

| Factor | Increases Severity | Decreases Severity |
|--------|-------------------|-------------------|
| Exploitability | No auth required, network-accessible | Requires local access, auth |
| Impact | Data loss, RCE, privilege escalation | Information disclosure only |
| Scope | Affects other components/users | Contained to single component |
| Data sensitivity | PII, PHI, financial, credentials | Public data, non-sensitive |
| Attack complexity | Simple, repeatable | Complex, requires chaining |

## Reporting Template

```
[SEVERITY] CWE-XXX: Short Title
File: path/to/file.ext:line_number
Description: Clear explanation of what's wrong
Impact: What an attacker could achieve
Remediation: Specific fix with code example
Compliance: SOC2 CCx.x, PCI x.x, HIPAA §xxx (if applicable)
```
