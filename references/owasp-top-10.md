# OWASP Top 10 (2021) — Security Checklist

## A01: Broken Access Control
- **Pattern**: Missing authorization checks, IDOR, path traversal
- **Grep**: `@AllowAnonymous|\[AllowAnonymous\]|\.permit|noAuth|skipAuth|isAdmin.*req\.(params|query|body)`
- **Fix**: Enforce least-privilege access, validate object ownership server-side

## A02: Cryptographic Failures
- **Pattern**: Weak hashing (MD5, SHA1), hardcoded keys, HTTP for sensitive data
- **Grep**: `MD5|SHA1|DES|RC4|ECB|http://.*password|http://.*token|http://.*api`
- **Fix**: Use AES-256-GCM, SHA-256+, TLS 1.2+, proper key management

## A03: Injection
- **Pattern**: SQL injection, command injection, LDAP injection, XSS
- **Grep**: `\bexec\b|eval\(|\.query\(.*\+|\.format\(.*SELECT|f".*SELECT|subprocess\.(call|run|Popen).*shell=True`
- **Fix**: Use parameterized queries, input validation, output encoding

## A04: Insecure Design
- **Pattern**: Missing rate limits, no business logic validation, no threat modeling
- **Check**: Rate limiting on auth endpoints, CAPTCHA on forms, transaction limits

## A05: Security Misconfiguration
- **Pattern**: Default credentials, verbose errors, unnecessary features
- **Grep**: `DEBUG\s*=\s*True|debug:\s*true|stack_trace|detailed_errors|password.*=.*(admin|root|test|123)`
- **Fix**: Harden defaults, disable debug in production, remove sample code

## A06: Vulnerable Components
- **Check**: Lock files for outdated packages, known CVE databases
- **Files**: `package-lock.json`, `requirements.txt`, `go.sum`, `*.csproj`

## A07: Authentication Failures
- **Pattern**: Weak passwords, missing MFA, session fixation
- **Grep**: `password.*min.*[0-5]|rememberMe|maxAge.*31536000`
- **Fix**: Strong password policies, MFA, secure session management

## A08: Software & Data Integrity
- **Pattern**: Insecure deserialization, missing integrity checks, untrusted CI/CD
- **Grep**: `pickle\.load|yaml\.load\(|BinaryFormatter|ObjectInputStream`
- **Fix**: Verify integrity (SRI, signatures), avoid unsafe deserialization

## A09: Logging & Monitoring Failures
- **Pattern**: Missing audit logs, logging sensitive data, no alerting
- **Grep**: `password.*log|token.*log|console\.log.*secret|logger.*credential`
- **Fix**: Log security events, never log secrets, implement alerting

## A10: Server-Side Request Forgery (SSRF)
- **Pattern**: User-controlled URLs in server-side requests
- **Grep**: `fetch\(.*req\.|requests\.get\(.*user|http\.Get\(.*param|HttpClient.*input`
- **Fix**: Allowlist URLs, validate schemas, block internal IPs
