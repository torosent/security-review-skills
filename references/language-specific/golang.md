# Go (Golang) Security Patterns — Comprehensive Reference

> Used by AI security review agent. Covers 18 vulnerability categories with grep patterns, CWE IDs, severity, and fixes.

---

## 1. SQL Injection — CWE-89 · CRITICAL

| Source | Grep Pattern |
|--------|-------------|
| database/sql | `db\.(Query\|Exec\|QueryRow)\(.*fmt\.Sprintf` `db\.(Query\|Exec\|QueryRow)\(.*\+\s*\w` |
| fmt building | `Sprintf\(.*(SELECT\|INSERT\|UPDATE\|DELETE\|WHERE\|FROM)` |
| GORM | `\.Raw\(.*fmt\.Sprintf` `\.Exec\(.*\+\s*\w` `\.Where\(.*fmt\.Sprintf` `\.Where\(.*\+\s*\w` |
| sqlx | `\.Select\(.*fmt\.Sprintf` `\.NamedExec\(.*\+` `\.Get\(.*Sprintf` |
| pgx | `pgx\.\w+\.(Query\|Exec)\(.*Sprintf` `conn\.(Query\|Exec)\(.*\+` |

**Fix**: Parameterized queries only: `db.Query("SELECT * FROM t WHERE id=$1", id)`. GORM: `.Where("id = ?", id)`. Never interpolate user input into SQL strings.

## 2. Command Injection — CWE-78 · CRITICAL

```
exec\.Command\("(sh|bash|cmd|powershell)"
exec\.Command\(.*"-c".*\+|exec\.Command\(.*"-c".*Sprintf
exec\.CommandContext\(.*fmt\.Sprintf|exec\.Command\(.*\+\s*\w
os\.StartProcess\(|syscall\.Exec\(|syscall\.ForkExec\(
```

**Fix**: `exec.Command(binary, arg1, arg2)` — pass args as separate params. Never invoke shell. Validate binary name against allowlist.

## 3. Path Traversal — CWE-22 · CRITICAL

```
filepath\.Join\(.*r\.(URL|Form|PostForm|Header)|filepath\.Join\(.*\.Param\(
os\.(Open|Create|ReadFile|WriteFile|Remove|Mkdir)\(.*r\.(URL|Form)
os\.(Open|Create|ReadFile|WriteFile)\(.*\+\s*\w
http\.ServeFile\(.*r\.URL|http\.ServeFile\(.*\.Param\(
ioutil\.ReadFile\(.*\+|ioutil\.WriteFile\(.*\+
```

**Zip Slip**: `archive/(zip|tar)` extraction without validating extracted paths:
```
zip\.OpenReader|tar\.NewReader|\.Next\(\).*\.Name
```

**Fix**: `cleaned := filepath.Clean(p); if !strings.HasPrefix(cleaned, baseDir) { reject }`. For archives: validate every entry name before extraction.

## 4. SSRF — CWE-918 · HIGH

```
http\.(Get|Post|Head|PostForm)\(.*r\.(URL|Form|PostForm)
http\.NewRequest\(.*r\.(URL|Form|PostForm)|http\.NewRequest\(.*user
url\.Parse\(.*r\.(URL|Form)|url\.Parse\(.*input|url\.Parse\(.*param
```

**Redirect following**: `CheckRedirect` absent on `http.Client` allows redirect to internal IPs.
**DNS rebinding**: Resolve hostname and validate IP before connecting.
**Metadata**: Block `169.254.169.254`, `[fd00::]`, link-local, loopback, private ranges.

**Fix**: Allowlist schemes (`https` only) + allowlist/blocklist hosts. Use custom `Transport.DialContext` to validate resolved IPs.

## 5. Insecure TLS — CWE-295 · HIGH

```
InsecureSkipVerify:\s*true
MinVersion:\s*tls\.Version(SSL30|TLS10|TLS11)
tls\.Config\{[^}]*InsecureSkipVerify
VerifyPeerCertificate:.*return\s+nil
CipherSuites:.*tls\.TLS_RSA_|CipherSuites:.*RC4|CipherSuites:.*3DES
```

**Fix**: `InsecureSkipVerify: false`, `MinVersion: tls.VersionTLS12`. Remove custom `VerifyPeerCertificate` that always returns nil. Use default cipher suites.

## 6. Race Conditions — CWE-362 · HIGH

| Pattern | Risk |
|---------|------|
| `go\s+func\s*\(` `go\s+\w+\(` | Goroutine spawning — check shared state |
| `var\s+\w+\s*(map\|=\s*make\(map)` | Maps are NOT goroutine-safe |
| `sync\.Mutex` without matching `\.Lock\(\)` | Declared but unused mutex |
| `sync\.Pool` | Items may retain sensitive data across reuse |

**TOCTOU**: `os.Stat` followed by `os.Open` — race between check and use.
**Goroutine leak**: Goroutines without `ctx.Done()`, `select`, or cancellation.

**Fix**: Use `sync.Mutex`/`sync.RWMutex`, `sync.Map` for concurrent maps, `sync/atomic` for counters. Run `go build -race` / `go test -race`.

## 7. Unsafe Package — CWE-242 · HIGH

```
"unsafe"|unsafe\.Pointer|unsafe\.Sizeof|unsafe\.Alignof|unsafe\.Offsetof
reflect\.SliceHeader|reflect\.StringHeader
#cgo\s+CFLAGS|#cgo\s+LDFLAGS
```

**Fix**: Avoid `unsafe` entirely. If required, document justification. For CGo: validate all pointers crossing the Go/C boundary. Never pass Go pointers to C code that retains them.

## 8. Integer Overflow — CWE-190 · HIGH

```
int32\(.*int64|int16\(.*int32|int8\(.*int16|uint8\(.*uint16
strconv\.Atoi\(.*\*|strconv\.Atoi\(.*make\(|strconv\.Atoi\(.*alloc
len\(.*\)\s*[\+\-\*]|cap\(.*\)\s*[\+\-\*]
```

**Fix**: Bounds-check before narrowing casts: `if v > math.MaxInt32 { error }`. Use `math/big` for large arithmetic. Validate `strconv.Atoi` results before using in allocations.

## 9. Template Injection — CWE-94 · HIGH

```
"text/template"|text/template\.New|text/template\.Must
template\.HTML\(|template\.JS\(|template\.CSS\(|template\.URL\(
\.Parse\(.*r\.(URL|Form|PostForm)|\.Parse\(.*user|\.Parse\(.*input
template\.New\(.*\.Parse\(.*\+
```

**Fix**: Use `html/template` (NOT `text/template`). Never pass user input to `template.Parse()`. Avoid wrapping user data in `template.HTML()` — this bypasses auto-escaping.

## 10. Cryptographic Misuse — CWE-327 · HIGH

| Pattern | Issue |
|---------|-------|
| `"crypto/md5"\|md5\.New\|md5\.Sum` | MD5 broken for security |
| `"crypto/sha1"\|sha1\.New\|sha1\.Sum` | SHA1 deprecated |
| `"crypto/des"\|des\.NewCipher\|des\.NewTripleDESCipher` | DES/3DES weak |
| `"crypto/rc4"\|rc4\.NewCipher` | RC4 broken |
| `"math/rand"\|rand\.New\(\|rand\.Intn\|rand\.Int\(\)` | Not cryptographically secure |
| `cipher\.NewCBCEncrypter\|cipher\.NewCBCDecrypter` | CBC mode — use GCM |
| `aes\.NewCipher\(.*\[\d+\]byte\{` | Hardcoded key |
| `rsa\.EncryptPKCS1v15` | Use OAEP instead |
| `iv\s*:?=\s*\[\]byte\{` `nonce\s*:?=\s*\[\]byte\{` | Static IV/nonce |

**Fix**: Use `crypto/rand` for random. Use `aes.NewCipher` + `cipher.NewGCM` (AEAD). Use `rsa.EncryptOAEP`. Generate keys/IVs with `crypto/rand.Read()`.

## 11. Authentication & JWT — CWE-287 · CRITICAL

```
"github\.com/dgrijalva/jwt-go"|dgrijalva/jwt-go
jwt\.Parse\(.*func.*return.*nil|SigningMethodNone|alg.*none
jwt\.(Parse|ParseWithClaims)\((?!.*Valid)
\.SignedString\(.*\[\]byte\("
token.*r\.(URL|Form)\.Get|token.*query\.Get
```

**Fix**: Use `github.com/golang-jwt/jwt/v5`. Enforce algorithm: `jwt.WithValidMethods([]string{"RS256"})`. Validate `iss`, `aud`, `exp`. Never put tokens in URL query params. Use strong secrets (≥256-bit).

## 12. HTTP Security — CWE-16 · MEDIUM–HIGH

```
Access-Control-Allow-Origin.*\*|AllowAllOrigins:\s*true|cors\.Default\(\)
AllowCredentials:\s*true.*AllowAllOrigins|cors\.AllowAll\(\)
Secure:\s*false|HttpOnly:\s*false|SameSite:\s*(0|http\.SameSiteNoneMode)
w\.Write\(.*err\.Error\(\)|fmt\.Fprint.*err\.Error\(\)|Fprintf.*err\b
ListenAndServe\((?!.*TLS)|http\.ListenAndServe\(":
w\.Header\(\)\.Set\(.*r\.(URL|Form)|w\.Header\(\)\.Add\(.*r\.(URL|Form)
```

**Fix**: Explicit CORS origins (no `*` with credentials). Set `Secure: true, HttpOnly: true, SameSite: Strict` on cookies. Use `ListenAndServeTLS`. Never reflect user input in response headers (CRLF injection).

## 13. Error Handling & Info Disclosure — CWE-209 · MEDIUM

```
_\s*,?\s*=\s*\w+\.\w+\(|_\s*=\s*(json|xml|yaml)\.(Marshal|Unmarshal)
w\.Write\(.*err\.Error\(\)|fmt\.Fprint.*(w|rw).*err
debug\.PrintStack\(\)|runtime\.Stack\(
log\.\w+\(.*password|log\.\w+\(.*secret|log\.\w+\(.*token|log\.\w+\(.*key
"net/http/pprof"|pprof\.Handler|/debug/pprof
panic\(.*r\.(URL|Form)|panic\(.*err
```

**Fix**: Never expose `err.Error()` to clients — return generic messages. Wrap handlers with `recover()`. Disable `pprof` in production. Redact secrets from logs.

## 14. File Upload — CWE-434 · MEDIUM

```
r\.ParseMultipartForm\(|r\.MultipartReader\(|r\.FormFile\(
\.Filename.*filepath\.Join|\.Filename.*os\.(Create|Open)
multipart\.File(?!.*DetectContentType)|ParseMultipartForm\(\s*0\s*\)
```

**Fix**: Validate Content-Type via `http.DetectContentType()`. Limit size: `r.ParseMultipartForm(10 << 20)`. Sanitize filename: strip path components. Use temp dirs with cleanup via `defer`.

## 15. Framework-Specific — CWE-20 · MEDIUM

| Framework | Pattern | Risk |
|-----------|---------|------|
| Gin | `c\.Bind\((?!.*Valid)\|c\.ShouldBind\((?!.*Valid)` | Missing input validation |
| Gin | `gin\.SetMode\(gin\.DebugMode\)` | Debug in production |
| Gin | `c\.HTML\(.*c\.(Query\|Param\|PostForm)` | XSS via template |
| Echo | `echo\.New\(\)(?!.*CSRF)` | Missing CSRF middleware |
| Echo | `c\.Bind\((?!.*Validate)` | Binding without validation |
| Fiber | `c\.Body\(\).*c\.Body\(\)` | Body reuse (fasthttp pool) |
| net/http | `http\.DefaultClient` | No timeout — DoS/hang |
| net/http | `http\.ListenAndServe\(":` | No TLS |

## 16. Context & Timeout — CWE-400 · MEDIUM

```
context\.Background\(\).*http\.(Get|Post|NewRequest)
context\.TODO\(\).*\.Do\(
http\.DefaultClient\.(Get|Post|Do)|&http\.Client\{\}\.
http\.Client\{(?!.*Timeout)
context\.WithCancel\((?!.*defer\s+cancel)
```

**Fix**: Always use request context: `req.WithContext(ctx)`. Set `http.Client{Timeout: 30*time.Second}`. Always `defer cancel()` after `context.WithTimeout/WithCancel`.

## 17. Memory Safety — CWE-119 · MEDIUM

```
\(\*reflect\.SliceHeader\)|reflect\.StringHeader
\[\]byte\(.*string\(|string\(.*\[\]byte\(.*go\s+func
sync\.Pool\{.*New:.*\[\]byte|sync\.Pool.*password|sync\.Pool.*secret
copy\(.*\[:.*\]\s*,.*\[:.*\])|append\(.*\[:.*\]\s*,
```

**Fix**: Avoid `reflect.SliceHeader` manipulation. Don't share `[]byte` across goroutines without sync. Zero sensitive data from `sync.Pool` items before returning. Use `copy()` to avoid aliasing.

## 18. Dependency & Module Security — CWE-829 · MEDIUM

```
replace\s+.*=>\s*\.\./ |replace\s+.*=>\s*\./|replace\s+.*=>\s*/
retract\s+\[|retract\s+v
GONOSUMCHECK|GONOSUMDB|GOFLAGS.*-insecure
GOPRIVATE.*\*|GONOSUMCHECK.*\*
```

**Fix**: Remove `replace` directives pointing to local paths before release. Run `go mod verify`. Don't set `GONOSUMCHECK=*`. Keep `GOPRIVATE` scoped narrowly. Use `govulncheck` to scan dependencies.

---

## Quick Severity Reference

| Severity | Categories |
|----------|------------|
| **CRITICAL** | SQL Injection, Command Injection, Path Traversal, JWT/Auth bypass |
| **HIGH** | SSRF, Insecure TLS, Race Conditions, Unsafe pkg, Integer Overflow, Template Injection, Crypto Misuse |
| **MEDIUM** | HTTP Security, Error Disclosure, File Upload, Framework issues, Context/Timeout, Memory Safety, Dependencies |

## Detection Commands

```bash
# Race detector
go build -race ./... && go test -race ./...
# Vulnerability scanner
govulncheck ./...
# Static analysis
staticcheck ./...
go vet ./...
# Find unsafe usage
grep -rn '"unsafe"' --include='*.go' .
# Find ignored errors
grep -rn '_ =' --include='*.go' . | grep -v '_test.go'
```
