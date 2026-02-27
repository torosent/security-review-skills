# Python Security Patterns — Comprehensive Reference

> For AI security review agents. Every pattern includes grep regex, CWE, severity, and fix.

---

## 1. Injection Attacks

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| SQL injection (format/fstring) | CWE-89 | CRITICAL | `\.execute\(.*(%s|\.format\(|f"|f'|\+)` | Parameterized queries: `cursor.execute("...%s", (val,))` |
| SQL injection (Django raw) | CWE-89 | CRITICAL | `\.raw\(.*(%\||\.format\(|f")` | Use ORM or `params=` arg: `.raw("...%s", [val])` |
| SQL injection (Django extra) | CWE-89 | CRITICAL | `\.extra\(` | Replace with ORM annotations/filters |
| SQL injection (SQLAlchemy text) | CWE-89 | CRITICAL | `text\(.*\.format\|text\(.*f"\|text\(.*%` | `text("...WHERE id=:id").bindparams(id=val)` |
| Command injection | CWE-78 | CRITICAL | `os\.system\(\|os\.popen\(\|subprocess\.\w+.*shell=True\|commands\.get` | `subprocess.run([cmd, arg], shell=False)` |
| Code injection | CWE-94 | CRITICAL | `eval\(\|exec\(\|compile\(.*user\|__import__\(.*input\|importlib.*user` | Use `ast.literal_eval()` for data; avoid eval entirely |
| LDAP injection | CWE-90 | HIGH | `ldap\.\w+\(.*%\|ldap\.\w+\(.*\.format\|ldap\.\w+\(.*f"` | Use `ldap3` with parameterized filters |
| Header injection (CRLF) | CWE-113 | HIGH | `\\r\\n.*header\|\\x0d\\x0a\|response\[.*\+.*input` | Strip `\r\n` from header values |
| Log injection | CWE-117 | MEDIUM | `logging\.\w+\(.*request\.\|logger\.\w+\(.*f".*user\|log\.\w+\(.*input` | Sanitize log inputs; use structured logging |
| XPath injection | CWE-643 | HIGH | `xpath\(.*\.format\|xpath\(.*f"\|xpath\(.*%` | Use parameterized XPath or lxml variables |

## 2. Insecure Deserialization (CWE-502)

| Source | Sev | Grep Pattern | Fix |
|--------|-----|-------------|-----|
| pickle | CRITICAL | `pickle\.(load\|loads\|Unpickler)\|cPickle\.(load\|loads)` | Use `json` or sign+verify before unpickling |
| yaml | CRITICAL | `yaml\.load\((?!.*Loader=.*SafeLoader)\|yaml\.unsafe_load` | `yaml.safe_load()` or `Loader=SafeLoader` |
| shelve | HIGH | `shelve\.open\(` | Use JSON/SQLite; shelve uses pickle internally |
| marshal | HIGH | `marshal\.load\(` | Use `json`; marshal is not safe for untrusted data |
| dill/cloudpickle | CRITICAL | `dill\.(load\|loads)\|cloudpickle\.(load\|loads)` | Avoid on untrusted data; use JSON |
| jsonpickle | CRITICAL | `jsonpickle\.decode\(` | Restrict allowed types or use plain JSON |
| XML/xmlrpc | HIGH | `xmlrpc\.client\|SimpleXMLRPCServer` | Validate/restrict types; use defusedxml |
| MessagePack ext | MEDIUM | `msgpack\.\w+pack.*raw=True\|ext_hook` | Use `raw=False`, validate ext types |

## 3. SSTI — Server-Side Template Injection (CWE-1336)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| Jinja2 from_string | CRITICAL | `Template\(.*request\|from_string\(.*user\|render_template_string\(` | Use `render_template()` with file-based templates |
| Mako user input | CRITICAL | `mako\.template\.Template\(.*request\|mako.*text=.*input` | Never pass user input as template source |
| Django mark_safe | HIGH | `mark_safe\(.*request\|mark_safe\(.*user\|safe\|.*user` | Avoid `mark_safe` on user-controlled data |
| format string attack | HIGH | `\.format\(.*request\|\.format\(\*\*\|".*"\s*%\s*\(.*request` | Use f-strings with known keys; never `user_str.format()` |

## 4. Path Traversal & File Ops (CWE-22, CWE-377)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| open() with user input | HIGH | `open\(.*request\.\|open\(.*user_\|open\(.*input` | Validate with `os.path.realpath()` + base prefix check |
| os.path.join traversal | HIGH | `os\.path\.join\(.*request\|os\.path\.join\(.*user` | Reject `..`; resolve then verify base |
| send_file traversal | HIGH | `send_file\(.*request\|send_from_directory\(.*request` | Use `safe_join()`; validate filename |
| Zip slip | HIGH | `zipfile\..*extract\(\|ZipFile.*extractall` | Check each entry name for `..` before extracting |
| Symlink attack | MEDIUM | `os\.symlink\(\|os\.readlink\(` | Use `os.path.realpath()` and verify resolved path |
| Temp file race | MEDIUM | `tempfile\.mktemp\(` | Use `tempfile.mkstemp()` or `NamedTemporaryFile` |
| shutil with user paths | HIGH | `shutil\.(copy\|move\|rmtree)\(.*request` | Validate and resolve all paths before operations |

## 5. SSRF — Server-Side Request Forgery (CWE-918)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| requests with user URL | HIGH | `requests\.(get\|post\|put\|delete\|head\|patch)\(.*request\.\|requests\.\w+\(.*user` | URL allowlist; block RFC1918 + link-local + metadata IPs |
| urllib user URL | HIGH | `urllib\.request\.urlopen\(.*input\|urllib\.request\.Request\(.*user` | Same as above |
| aiohttp user URL | HIGH | `aiohttp\.ClientSession.*\.get\(.*user\|session\.(get\|post).*request\.` | Validate + resolve DNS before request |
| httpx user URL | HIGH | `httpx\.(get\|post\|AsyncClient).*user\|httpx\.\w+\(.*request\.` | URL allowlist; block internal ranges |
| Cloud metadata | CRITICAL | `169\.254\.169\.254\|metadata\.google\|metadata\.azure` | Block metadata IPs in URL validation |

## 6. Cryptographic Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Insecure random | CWE-330 | HIGH | `random\.(random\|randint\|choice\|randrange)\(.*token\|random\.\w+.*password\|random\.\w+.*secret\|random\.\w+.*key` | `secrets.token_hex()`, `secrets.token_urlsafe()` |
| Weak password hash | CWE-328 | CRITICAL | `hashlib\.(md5\|sha1)\(.*password\|md5\(.*pass\|\.hexdigest\(\).*password` | Use `bcrypt`, `argon2`, or `scrypt` |
| Hardcoded secrets | CWE-798 | CRITICAL | `(password\|secret\|api_key\|token\|private_key)\s*=\s*['"][^'"]{8,}` | Environment variables or secret manager |
| Timing attack | CWE-208 | HIGH | `==.*hmac\|==.*digest\|==.*hash\|==.*token\|password\s*==` | `hmac.compare_digest(a, b)` |
| TLS verify disabled | CWE-295 | HIGH | `verify\s*=\s*False\|CERT_NONE\|check_hostname\s*=\s*False` | Always `verify=True`; use cert bundles |
| ECB mode | CWE-327 | HIGH | `MODE_ECB\|AES\.new\(.*ECB` | Use AES-GCM or AES-CBC with random IV |
| Static IV | CWE-329 | HIGH | `iv\s*=\s*b['"]` | Generate random IV per encryption: `os.urandom(16)` |

## 7. Django Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| DEBUG in prod | CWE-215 | HIGH | `DEBUG\s*=\s*True` | `DEBUG = False` in production; use env var |
| ALLOWED_HOSTS wildcard | CWE-16 | HIGH | `ALLOWED_HOSTS\s*=\s*\['\*'\]` | Set explicit hostnames |
| SECRET_KEY hardcoded | CWE-798 | CRITICAL | `SECRET_KEY\s*=\s*['"]` | Load from env: `os.environ['SECRET_KEY']` |
| CSRF disabled | CWE-352 | HIGH | `@csrf_exempt\|csrf_exempt` | Remove; use CSRF tokens properly |
| No SSL redirect | CWE-319 | MEDIUM | `SECURE_SSL_REDIRECT\s*=\s*False` | `SECURE_SSL_REDIRECT = True` |
| Unsafe redirect | CWE-601 | HIGH | `HttpResponseRedirect\(.*request\.\|redirect\(.*request\.GET` | Validate redirect URL against allowlist |
| Session cookie insecure | CWE-614 | MEDIUM | `SESSION_COOKIE_SECURE\s*=\s*False\|SESSION_COOKIE_HTTPONLY\s*=\s*False` | Set both to `True` |
| CORS misconfiguration | CWE-942 | HIGH | `CORS_ALLOW_ALL_ORIGINS\s*=\s*True\|CORS_ORIGIN_ALLOW_ALL` | Set explicit `CORS_ALLOWED_ORIGINS` |
| Mass assignment | CWE-915 | MEDIUM | `fields\s*=\s*'__all__'\|exclude\s*=\s*\[\]` | Explicit `fields = [...]` in forms/serializers |

## 8. Flask Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Debug mode prod | CWE-215 | HIGH | `app\.run\(.*debug\s*=\s*True\|DEBUG\s*=\s*True` | `debug=False`; use env var |
| Hardcoded secret key | CWE-798 | CRITICAL | `app\.secret_key\s*=\s*['"\|SECRET_KEY.*=\s*['"]` | `app.secret_key = os.environ[...]` |
| Autoescape off | CWE-79 | HIGH | `autoescape\s*=\s*False\|Markup\(.*request` | Keep `autoescape=True` (Jinja2 default) |
| No CSRF protection | CWE-352 | HIGH | `WTF_CSRF_ENABLED\s*=\s*False\|CSRFProtect` (missing) | Use Flask-WTF CSRFProtect |
| Unsafe file upload | CWE-434 | HIGH | `request\.files.*save\(\|\.save\(.*filename` | `werkzeug.utils.secure_filename()`; validate type+size |

## 9. FastAPI Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing validation | CWE-20 | MEDIUM | `def\s+\w+\(.*:\s*str[,)]` (raw str params without Pydantic) | Use Pydantic models with validators |
| CORS allow all | CWE-942 | HIGH | `allow_origins\s*=\s*\["\*"\]\|allow_origins=\["` | Restrict to specific origins |
| Raw SQL in endpoint | CWE-89 | CRITICAL | `\.execute\(.*f"\|text\(.*f"\|\.execute\(.*\.format` | Use ORM or parameterized queries |
| Response model leak | CWE-200 | MEDIUM | `response_model\s*=\s*None\|exclude.*=\s*False` | Define explicit `response_model` with limited fields |

## 10. Async-Specific Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing await | CWE-691 | HIGH | `if\s+check_\w+\((?!.*await)\|if\s+verify_\w+\((?!.*await)\|if\s+is_authorized\((?!.*await)` | Always `await` async security checks |
| Shared mutable state | CWE-362 | HIGH | `global\s+\w+.*async\|shared_\w+\s*=\s*\{\}` | Use `asyncio.Lock()` or request-scoped state |
| Event loop blocking | CWE-400 | MEDIUM | `time\.sleep\(\|\.read\(\).*async\s+def` | Use `await asyncio.sleep()` and async I/O |

## 11. XXE — XML External Entity (CWE-611)

| Source | Sev | Grep Pattern | Fix |
|--------|-----|-------------|-----|
| lxml/etree | HIGH | `etree\.parse\(\|etree\.fromstring\(\|etree\.iterparse\(` | Use `defusedxml.lxml`; or `XMLParser(resolve_entities=False, no_network=True)` |
| minidom | HIGH | `minidom\.parse\(\|minidom\.parseString\(` | Use `defusedxml.minidom` |
| SAX/pulldom | HIGH | `sax\.parse\(\|pulldom\.parse\(` | Use `defusedxml.sax` / `defusedxml.pulldom` |
| expat | HIGH | `xml\.parsers\.expat` | Use `defusedxml.expat` |
| xmlrpc | HIGH | `xmlrpc\.client\|xmlrpc\.server` | Restrict methods; validate all inputs |

## 12. ReDoS — Regular Expression DoS (CWE-1333)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| User input in regex | HIGH | `re\.compile\(.*request\|re\.compile\(.*user\|re\.search\(.*input.*,.*input` | Use `re.escape()` on user input; set timeout |
| Catastrophic backtracking | MEDIUM | `\(\.\*\)\+\|\(\.\+\)\+\|\(\[^\\]\]\*\)\+` (nested quantifiers in patterns) | Avoid nested quantifiers; use atomic groups or `re2` |

## 13. File Upload Security (CWE-434)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| No type validation | HIGH | `request\.files\[.*\.save\(` | Check MIME type + magic bytes; allowlist extensions |
| Path traversal in name | HIGH | `\.filename.*open\(\|\.filename.*save\(` | `secure_filename()` + UUID rename |
| No size limit | MEDIUM | `MAX_CONTENT_LENGTH` (missing) | Set `MAX_CONTENT_LENGTH` in Flask/Django |

## 14. Subprocess & Process Security (CWE-78)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| shell=True | CRITICAL | `subprocess\.\w+\(.*shell\s*=\s*True` | Use arg list: `subprocess.run(["cmd", arg])` |
| os.system/popen | CRITICAL | `os\.system\(\|os\.popen\(` | Replace with `subprocess.run([...])` |
| Env var injection | MEDIUM | `env=.*request\|os\.environ\.update\(.*user` | Allowlist env vars; never pass user data directly |

## 15. Logging & Info Disclosure (CWE-532, CWE-209)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| Logging secrets | HIGH | `log.*password\|log.*token\|log.*secret\|log.*api_key\|print\(.*password` | Redact sensitive fields; use structured logging |
| Stack traces exposed | MEDIUM | `traceback\.format_exc\(\).*response\|traceback\.print_exc.*return` | Return generic errors; log details server-side |
| Debug endpoints | MEDIUM | `@app\.route.*debug\|/debug/\|/admin.*debug` | Remove or protect with auth + IP restriction |

## 16. Type Safety Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing type hints on auth | CWE-20 | MEDIUM | `def\s+(authenticate\|authorize\|verify\|check_perms)\(.*\):\s*$` (no return type) | Add type hints; use `-> bool` or typed returns |
| Dynamic attr access | CWE-915 | HIGH | `getattr\(.*request\|setattr\(.*request\|__getattr__.*user` | Allowlist attribute names; avoid dynamic access |
| Any type masking | CWE-20 | LOW | `:\s*Any\s*[=,)]` in security modules | Use specific types; avoid `Any` on security boundaries |

---

## Quick-Reference: Combined Critical Grep Patterns

```
# Run all critical patterns at once:
eval\(|exec\(|os\.system\(|subprocess.*shell=True|pickle\.load|yaml\.load\((?!.*SafeLoader)
\.execute\(.*f"|\.execute\(.*\.format|\.raw\(.*f"|verify\s*=\s*False
Template\(.*request|render_template_string\(|mark_safe\(.*request
SECRET_KEY\s*=\s*['"]|password\s*=\s*['"][^'"]{8,}|DEBUG\s*=\s*True
hashlib\.(md5|sha1)\(.*password|random\.\w+.*token|==.*digest
```
