# JavaScript / TypeScript Security Patterns

> Comprehensive reference for AI-driven security review. Each entry has grep-able patterns, CWE, severity, and fix.

---

## 1. Injection Attacks

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| SQL Injection | CWE-89 | Critical | `query\(.*\$\{|query\(.*\+.*req\.|\. raw\(.*\$\{|\.raw\(.*\+|knex\.raw\(.*\$\{|\$queryRaw.*\$\{` | Use parameterized queries / prepared statements |
| NoSQL Injection | CWE-943 | Critical | `\$where.*req\.|\$regex.*req\.|\. find\(.*req\.body|\.findOne\(.*req\.query|\$gt.*req\.|\$ne.*req\.|\$or.*req\.` | Validate/sanitize `$` operators; use schema validation |
| Command Injection | CWE-78 | Critical | `child_process\.exec\(.*req\.|child_process\.exec\(.*\$\{|execSync\(.*\$\{|spawn\(.*shell:\s*true|\.exec\(.*user` | Use `execFile`/`spawn` with args array, no shell |
| Code Injection | CWE-94 | Critical | `eval\(|new Function\(|vm\.runIn|vm\.createContext|setTimeout\(.*req\.|setInterval\(.*req\.` | Never eval user input; use safe parsers |
| Template Injection | CWE-1336 | Critical | `ejs\.render\(.*req\.|pug\.render\(.*req\.|Handlebars\.compile\(.*req\.|nunjucks\.renderString\(.*req\.` | Never pass user input as template source |
| LDAP Injection | CWE-90 | High | `ldap\.\(search\|bind\).*req\.|filter:.*\$\{.*req\.` | Escape special LDAP chars; use parameterized filters |
| Header/CRLF Injection | CWE-113 | High | `setHeader\(.*req\.|writeHead\(.*req\.|res\.redirect\(.*req\.` | Strip `\r\n` from header values; validate redirect URLs |
| Log Injection | CWE-117 | Medium | `console\.log\(.*req\.|logger\.\(info\|warn\|error\)\(.*req\.` | Sanitize newlines/control chars before logging |

## 2. Cross-Site Scripting (XSS) — CWE-79

| Context | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| DOM XSS | Critical | `innerHTML\s*=|outerHTML\s*=|document\.write\(|insertAdjacentHTML\(|\.createContextualFragment\(` | Use `textContent`; sanitize with DOMPurify |
| React | Critical | `dangerouslySetInnerHTML|href\s*=.*javascript:|href\s*=\s*\{.*user|__html.*req\.|__html.*param` | Avoid `dangerouslySetInnerHTML`; validate URLs |
| Angular | Critical | `bypassSecurityTrust\(Html\|Url\|Script\|ResourceUrl\)|\[innerHTML\]\s*=|DomSanitizer` | Minimize bypass usage; audit each instance |
| Vue | Critical | `v-html\s*=|v-html=.*user|\$slots.*v-html` | Use `v-text` or sanitize input before `v-html` |
| jQuery | High | `\.html\(.*\$\(|\.html\(.*req\.|\.append\(.*\$\(|\$\.globalEval|\.after\(.*user` | Use `.text()`; sanitize with DOMPurify |
| Next.js SSR | High | `getServerSideProps.*password|getServerSideProps.*secret|getServerSideProps.*token|__NEXT_DATA__` | Filter sensitive data from SSR props |
| Reflected | High | `res\.send\(.*req\.|res\.write\(.*req\.|res\.end\(.*req\.query` | Encode output; use template engine auto-escaping |

## 3. Authentication & Session

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| JWT alg:none | CWE-347 | Critical | `algorithms.*none|algorithm.*none|verify\(.*\{.*algorithms|jwt\.decode\(` | Explicitly set `algorithms: ['RS256']`; always verify |
| JWT weak secret | CWE-326 | Critical | `sign\(.*["']secret["']|sign\(.*["']password["']|sign\(.*["']key["']|jwt.*hardcoded` | Use strong secrets (≥256-bit); rotate keys |
| JWT no expiry | CWE-613 | High | `sign\(.*\{(?!.*exp)(?!.*expiresIn)` | Always set `expiresIn` |
| Weak password hash | CWE-916 | Critical | `md5\(.*password|sha1\(.*password|createHash\(["']md5["']\).*password|createHash\(["']sha1["']\).*password` | Use bcrypt/scrypt/argon2 |
| Plaintext password | CWE-256 | Critical | `password\s*[:=]\s*["'][^"']+["']|password.*plaintext|\.password\s*===` | Never store/compare plaintext; use bcrypt.compare |
| No rate limit | CWE-307 | High | `\/login|\/auth|\/signin|\/api\/auth` + absence of `rate.limit|rateLimit|express-rate-limit|bottleneck` | Add rate limiting to auth endpoints |
| OAuth open redirect | CWE-601 | High | `redirect_uri.*req\.|callback.*req\.query|returnUrl.*req\.` | Whitelist redirect URIs; validate against allow-list |
| Session fixation | CWE-384 | High | `req\.session(?!.*regenerate)|session\.id.*=` | Call `req.session.regenerate()` after login |

## 4. Prototype Pollution — CWE-1321

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| Deep merge | Critical | `merge\(.*req\.|defaultsDeep\(|_. merge\(|deepmerge\(|Object\.assign\(.*req\.body|\.\.\. req\.body` | Use `Object.create(null)`; block `__proto__`, `constructor`, `prototype` keys |
| JSON.parse __proto__ | High | `JSON\.parse\(.*req\.|JSON\.parse\(.*body|JSON\.parse\(.*user` | Use reviver function to strip dangerous keys |
| qs library | High | `qs\.parse\(|querystring\.parse\(` | Set `allowPrototypes: false` (qs default); limit depth |
| Recursive set | High | `\[.*\]\s*=|lodash\.set|_. set\(|setPath\(` | Validate property paths; reject dunder properties |

## 5. SSRF — CWE-918

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| User-controlled URL | Critical | `fetch\(.*req\.|axios\.\(get\|post\)\(.*req\.|got\(.*req\.|http\.get\(.*req\.|request\(.*req\.|urllib\.request\(.*req\.` | Validate URL against allow-list; block internal IPs |
| Cloud metadata | Critical | `169\.254\.169\.254|metadata\.google|metadata\.azure` | Block metadata IP ranges in URL validation |
| DNS rebinding | High | `followRedirect|maxRedirects|redirect.*follow` | Resolve DNS before request; re-check after redirect |
| URL parsing bypass | High | `new URL\(.*req\.|url\.parse\(.*req\.` | Use consistent URL parser; validate hostname post-parse |

## 6. Path Traversal — CWE-22

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| fs with user input | Critical | `fs\.\(readFile\|writeFile\|unlink\|access\|stat\|createReadStream\|createWriteStream\).*req\.|sendFile\(.*req\.` | `path.resolve()` + verify starts with base dir |
| Static file serve | High | `express\.static\(.*req\.|serve-static|\.sendFile\(` | Configure root dir; disable dotfiles |
| Zip slip | High | `unzip|extract|archiver|adm-zip|tar\.extract|entry\.path|entryName` | Validate extracted paths stay within target dir |
| Symlink attacks | Medium | `fs\.symlink|fs\.readlink|lstat` | Use `fs.realpath()` to resolve; verify resolved path |

## 7. Insecure Deserialization — CWE-502

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| Dangerous libs | Critical | `require\(["']node-serialize["']\)|require\(["']funcster["']\)|require\(["']cryo["']\)|serialize-javascript` | Use `JSON.parse()` only; remove dangerous libs |
| YAML unsafe | Critical | `yaml\.load\((?!.*safe)|js-yaml\.load\((?!.*JSON_SCHEMA)|safeLoad` is deprecated | Use `yaml.load(str, { schema: JSON_SCHEMA })` |
| Prototype via deser | High | `__proto__|constructor.*prototype` in JSON/YAML input | Strip dangerous keys in deserialization reviver |

## 8. Cryptographic Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Insecure random | CWE-330 | High | `Math\.random\(\)` (in security context) | Use `crypto.randomBytes()` / `crypto.randomUUID()` |
| Weak hash | CWE-328 | High | `createHash\(["']md5["']\)|createHash\(["']sha1["']\)|md5\(|sha1\(` (for passwords/tokens) | Use SHA-256+ for integrity; bcrypt/argon2 for passwords |
| Hardcoded keys | CWE-798 | Critical | `["']\w{32,}["'].*\(key\|secret\|iv\|encrypt\)|createCipher\(.*["'][^"']{16,}["']|AES.*["'][0-9a-f]{32}` | Use env vars / secret managers; never commit keys |
| ECB mode | CWE-327 | High | `createCipher\(|ECB|aes-128-ecb|aes-256-ecb` | Use `createCipheriv` with CBC/GCM + random IV |
| Timing attack | CWE-208 | Medium | `===.*token|===.*secret|===.*hash|==.*password|\.equals\(.*token` | Use `crypto.timingSafeEqual()` for secret comparison |

## 9. ReDoS — CWE-1333

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| User regex | High | `new RegExp\(.*req\.|RegExp\(.*user|RegExp\(.*input|RegExp\(.*param|RegExp\(.*query` | Never build regex from user input; use `re2` library |
| Catastrophic patterns | Medium | `(\. *){2,}|\(\[^\\\]\]\*\)\+|\(\.+\)\+|\(\\w\+\)\+` | Audit regex for nested quantifiers; use safe-regex |

## 10. Dependency & Supply Chain

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Postinstall scripts | CWE-506 | High | `"postinstall"|"preinstall"|"install"` in package.json | Audit postinstall scripts; use `--ignore-scripts` |
| Unpinned deps | CWE-1104 | Medium | `["']\*["']|["']latest["']|["']>=|["']>\d` in package.json | Pin exact versions; use lockfiles |
| No lockfile | CWE-1104 | Medium | absence of `package-lock.json|yarn.lock|pnpm-lock.yaml` | Commit lockfiles to source control |

## 11. Security Headers & CORS

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing headers | CWE-693 | Medium | Absence of `helmet|Content-Security-Policy|X-Frame-Options|Strict-Transport-Security` | Use `helmet` middleware; set CSP, HSTS, X-Frame |
| CORS wildcard | CWE-942 | High | `Access-Control-Allow-Origin.*\*|cors\(\{.*origin:\s*true|credentials.*true.*origin.*\*` | Whitelist specific origins; never `*` with credentials |
| Insecure cookies | CWE-614 | High | `cookie\((?!.*httpOnly)|cookie\((?!.*secure)|cookie\((?!.*sameSite)|session\((?!.*secure)` | Set `httpOnly`, `secure`, `sameSite: 'strict'` |

## 12. File Upload — CWE-434

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| No type validation | High | `multer\(|upload\.\(single\|array\|fields\)|formidable|busboy` + no `fileFilter|mimetype|allowedTypes` | Validate MIME type + extension; check magic bytes |
| Path traversal name | High | `originalname|filename.*req\.|file\.name` | Sanitize filenames; generate UUID names |
| No size limit | Medium | `multer\((?!.*limits)|formidable\((?!.*maxFileSize)` | Set `limits: { fileSize: MAX }` |

## 13. WebSocket Security — CWE-1385

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| No origin check | High | `new WebSocket\.Server\((?!.*verifyClient)|wss\.\(on\)\(["']connection["']` | Validate `Origin` header in `verifyClient` |
| No WS auth | High | `ws\.on\(["']message["']\)` without auth check | Authenticate on connection; verify tokens |
| WS message injection | Medium | `ws\.send\(.*JSON\.stringify\(.*req\.|broadcast\(.*data` | Validate/sanitize messages; enforce schema |

## 14. GraphQL Security

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Introspection in prod | CWE-200 | High | `introspection:\s*true|__schema|__type` | Disable introspection in production |
| No depth limit | CWE-400 | High | `graphql|ApolloServer|express-graphql` + no `depthLimit|queryComplexity|maxDepth` | Use `graphql-depth-limit`; set complexity limits |
| No field auth | CWE-862 | High | `@Resolver|resolvers\s*[:=]` + no `@Authorized|@Auth|context\.user` | Add per-field/resolver authorization checks |
| Batching attack | CWE-770 | Medium | `allowBatchedHttpRequests|batch.*true` | Disable batching or limit batch size |

## 15. Framework-Specific

| Framework | Vuln | Sev | Grep Pattern | Fix |
|-----------|------|-----|-------------|-----|
| Express | Trust proxy misc | High | `trust proxy.*true|app\.set\(["']trust proxy["'],\s*true\)` | Set specific trusted proxy IPs |
| Express | Stack trace leak | Medium | `app\.use\(.*err.*req.*res.*next.*\)\s*\{(?!.*NODE_ENV)` | Hide stack traces in production |
| Express | Body limit | Medium | `bodyParser\.\(json\|urlencoded\)\((?!.*limit)|express\.json\((?!.*limit)` | Set `limit: '100kb'` on body parsers |
| Next.js | API exposure | High | `pages\/api|app\/api.*route\.\(ts\|js\)` + no auth middleware | Add authentication to API routes |
| Next.js | Data leak SSR | High | `getServerSideProps|getStaticProps` returning sensitive fields | Filter sensitive data before returning props |
| Nest.js | Guard bypass | High | `@Public\(\)|@SkipAuth|@NoAuth` | Audit all guard bypass decorators |
| Nest.js | No validation | High | `@Body\(\)|@Query\(\)|@Param\(\)` + no `ValidationPipe|class-validator` | Use `ValidationPipe` globally; add DTOs |

## 16. TypeScript-Specific

| Pattern | Sev | Grep Pattern | Fix |
|---------|-----|-------------|-----|
| Type assertion bypass | Medium | `as any|as unknown as|<any>` | Avoid `as any`; use proper types/type guards |
| Suppressed errors | Medium | `@ts-ignore|@ts-expect-error|@ts-nocheck` near security code | Review all suppression comments; fix types |
| Broad types | Low | `Record<string,\s*any>|:\s*any[;\s]|:\s*object[;\s]` | Use strict types; define interfaces for all inputs |

---

## Quick Scan Checklist

**Critical — must flag immediately:**
- `eval(`, `new Function(`, `child_process.exec(` with user input
- `dangerouslySetInnerHTML`, `innerHTML =`, `v-html` with user data
- `$where`, `$regex` with request data (NoSQL injection)
- `query(` / `.raw(` with template literals (SQL injection)
- `node-serialize`, `funcster`, `cryo` (deserialization)
- `Math.random()` for tokens/secrets
- Hardcoded keys/secrets in source

**High — review in context:**
- `fetch`/`axios`/`got` with user-controlled URLs (SSRF)
- `fs.*` operations with request parameters (path traversal)
- JWT with `algorithms: ['none']` or hardcoded secrets
- `merge(`/`deepmerge(`/`Object.assign(` with request body (prototype pollution)
- Missing `helmet`, rate limiting, CORS restrictions
- `new RegExp(` with user input (ReDoS)
