# Secrets Detection Patterns

## High-Confidence Regex Patterns

Scan all files (excluding binaries, node_modules, vendor, .git) with these patterns:

### API Keys & Tokens
```
AKIA[0-9A-Z]{16}                          # AWS Access Key
AIza[0-9A-Za-z\-_]{35}                    # Google API Key
sk-[a-zA-Z0-9]{20,}                       # OpenAI/Stripe Secret Key
ghp_[a-zA-Z0-9]{36}                       # GitHub Personal Access Token
gho_[a-zA-Z0-9]{36}                       # GitHub OAuth Token
ghs_[a-zA-Z0-9]{36}                       # GitHub Server Token
xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}  # Slack Bot Token
SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}  # SendGrid API Key
sk_live_[a-zA-Z0-9]{24,}                  # Stripe Live Key
```

### Passwords & Secrets in Config
```
password\s*[:=]\s*["'][^"']{3,}["']
passwd\s*[:=]\s*["'][^"']{3,}["']
secret\s*[:=]\s*["'][^"']{3,}["']
api[_-]?key\s*[:=]\s*["'][^"']{3,}["']
auth[_-]?token\s*[:=]\s*["'][^"']{3,}["']
access[_-]?token\s*[:=]\s*["'][^"']{3,}["']
connection[_-]?string\s*[:=]\s*["'][^"']{3,}["']
```

### Private Keys & Certificates
```
-----BEGIN\s*(RSA|DSA|EC|OPENSSH)?\s*PRIVATE KEY-----
-----BEGIN\s*CERTIFICATE-----
```

### Connection Strings
```
(mongodb|postgres|mysql|redis|amqp):\/\/[^:\s]+:[^@\s]+@
Server=.*Password=
Data Source=.*Password=
```

## Files to Prioritize

| Pattern | Risk |
|---------|------|
| `.env`, `.env.*` | Environment variables with secrets |
| `*.config`, `*.cfg`, `*.ini` | Configuration files |
| `**/config/**`, `**/settings/**` | Config directories |
| `docker-compose*.yml` | Container env vars |
| `*.tfvars`, `terraform.tfstate` | Terraform state/vars |
| `**/ci/**`, `.github/workflows/*` | CI/CD pipeline secrets |
| `appsettings*.json`, `web.config` | .NET configuration |

## Exclusions (Reduce False Positives)

Skip matches in: `**/test/**`, `**/mock/**`, `**/__test__/**`, `**/fixture*/**`, `*.test.*`, `*.spec.*`, `**/example*/**`, `**/sample*/**`, `**/node_modules/**`, `**/vendor/**`, `**/.git/**`

Also skip if value is: `<placeholder>`, `changeme`, `xxx`, `TODO`, `REPLACE_ME`, empty, or references an env var (`${...}`, `process.env`, `os.environ`).
