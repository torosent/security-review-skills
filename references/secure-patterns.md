# Secure Coding Patterns & Remediations

## Input Validation

### Pattern: Validate-Sanitize-Use
1. **Validate** type, length, range, and format at the boundary
2. **Sanitize** by encoding/escaping for the target context
3. **Use** the validated, sanitized value

### Allowlist Over Denylist
```
# BAD — denylist (bypassable)
if "<script>" not in user_input:

# GOOD — allowlist
if re.match(r'^[a-zA-Z0-9_-]{1,64}$', user_input):
```

## Authentication & Session

| Pattern | Implementation |
|---------|---------------|
| Password hashing | bcrypt/scrypt/argon2 with salt, cost ≥ 10 |
| Session tokens | `crypto.randomBytes(32)`, not `Math.random()` |
| Token expiry | Access: 15-60 min, Refresh: 7-30 days |
| Rate limiting | Auth endpoints: 5-10 attempts per minute |
| MFA | TOTP (RFC 6238) or WebAuthn/FIDO2 |

## Database Queries

```python
# BAD — SQL injection
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# GOOD — parameterized
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

## Secrets Management

| Instead of... | Use... |
|--------------|--------|
| Hardcoded strings | Environment variables |
| `.env` in repo | Secret manager (Key Vault, AWS Secrets Manager) |
| Config files with secrets | Runtime injection via CI/CD |
| Shared secrets | Per-service credentials with rotation |

## Output Encoding

| Context | Encoding |
|---------|----------|
| HTML body | HTML entity encoding (`&lt;`, `&gt;`) |
| HTML attribute | Attribute encoding + quote wrapping |
| JavaScript | JavaScript hex encoding |
| URL parameter | URL/percent encoding |
| CSS | CSS hex encoding |
| SQL | Parameterized queries (not encoding) |

## Cryptography

| Use Case | Recommended |
|----------|-------------|
| Symmetric encryption | AES-256-GCM |
| Hashing (integrity) | SHA-256 or SHA-3 |
| Password hashing | Argon2id, bcrypt, scrypt |
| Key exchange | ECDH with P-256+ |
| Signing | Ed25519 or ECDSA P-256 |
| Random values | OS CSPRNG (`crypto.randomBytes`, `os.urandom`, `crypto/rand`) |

**Never use**: MD5, SHA1 (for security), DES, 3DES, RC4, ECB mode, custom crypto.

## Error Handling

```
# BAD — leaks internals
return {"error": str(exception), "stack": traceback.format_exc()}

# GOOD — safe error
logger.error(f"Operation failed: {exception}", exc_info=True)
return {"error": "An internal error occurred", "reference": error_id}
```

## HTTP Security Headers

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 0
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
```
