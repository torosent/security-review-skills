# Python Security Patterns — Comprehensive Reference

> For AI security review agents. Every pattern includes grep regex, CWE, severity, and fix.

---

## 1. Injection Attacks

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| SQL injection (format/fstring) | CWE-89 | Critical | `\.execute\(.*(%s|\.format\(|f"|f'|\+)` | Parameterized queries: `cursor.execute("...%s", (val,))` |
| SQL injection (Django raw) | CWE-89 | Critical | `\.raw\(.*(%\||\.format\(|f")` | Use ORM or `params=` arg: `.raw("...%s", [val])` |
| SQL injection (Django extra) | CWE-89 | Critical | `\.extra\(` | Replace with ORM annotations/filters |
| SQL injection (SQLAlchemy text) | CWE-89 | Critical | `text\(.*\.format\|text\(.*f"\|text\(.*%` | `text("...WHERE id=:id").bindparams(id=val)` |
| Command injection | CWE-78 | Critical | `os\.system\(\|os\.popen\(\|subprocess\.\w+.*shell=True\|commands\.get` | `subprocess.run([cmd, arg], shell=False)` |
| Code injection | CWE-94 | Critical | `eval\(\|exec\(\|compile\(.*user\|__import__\(.*input\|importlib.*user` | Use `ast.literal_eval()` for data; avoid eval entirely |
| LDAP injection | CWE-90 | High | `ldap\.\w+\(.*%\|ldap\.\w+\(.*\.format\|ldap\.\w+\(.*f"` | Use `ldap3` with parameterized filters |
| Header injection (CRLF) | CWE-113 | High | `\\r\\n.*header\|\\x0d\\x0a\|response\[.*\+.*input` | Strip `\r\n` from header values |
| Log injection | CWE-117 | Medium | `logging\.\w+\(.*request\.\|logger\.\w+\(.*f".*user\|log\.\w+\(.*input` | Sanitize log inputs; use structured logging |
| XPath injection | CWE-643 | High | `xpath\(.*\.format\|xpath\(.*f"\|xpath\(.*%` | Use parameterized XPath or lxml variables |

## 2. Insecure Deserialization (CWE-502)

| Source | Sev | Grep Pattern | Fix |
|--------|-----|-------------|-----|
| pickle | Critical | `pickle\.(load\|loads\|Unpickler)\|cPickle\.(load\|loads)` | Use `json` or sign+verify before unpickling |
| yaml | Critical | `yaml\.load\((?!.*Loader=.*SafeLoader)\|yaml\.unsafe_load` | `yaml.safe_load()` or `Loader=SafeLoader` |
| shelve | High | `shelve\.open\(` | Use JSON/SQLite; shelve uses pickle internally |
| marshal | High | `marshal\.load\(` | Use `json`; marshal is not safe for untrusted data |
| dill/cloudpickle | Critical | `dill\.(load\|loads)\|cloudpickle\.(load\|loads)` | Avoid on untrusted data; use JSON |
| jsonpickle | Critical | `jsonpickle\.decode\(` | Restrict allowed types or use plain JSON |
| XML/xmlrpc | High | `xmlrpc\.client\|SimpleXMLRPCServer` | Validate/restrict types; use defusedxml |
| MessagePack ext | Medium | `msgpack\.\w+pack.*raw=True\|ext_hook` | Use `raw=False`, validate ext types |

## 3. SSTI — Server-Side Template Injection (CWE-1336)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| Jinja2 from_string | Critical | `Template\(.*request\|from_string\(.*user\|render_template_string\(` | Use `render_template()` with file-based templates |
| Mako user input | Critical | `mako\.template\.Template\(.*request\|mako.*text=.*input` | Never pass user input as template source |
| Django mark_safe | High | `mark_safe\(.*request\|mark_safe\(.*user\|safe\|.*user` | Avoid `mark_safe` on user-controlled data |
| format string attack | High | `\.format\(.*request\|\.format\(\*\*\|".*"\s*%\s*\(.*request` | Use f-strings with known keys; never `user_str.format()` |

## 4. Path Traversal & File Ops (CWE-22, CWE-377)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| open() with user input | High | `open\(.*request\.\|open\(.*user_\|open\(.*input` | Validate with `os.path.realpath()` + base prefix check |
| os.path.join traversal | High | `os\.path\.join\(.*request\|os\.path\.join\(.*user` | Reject `..`; resolve then verify base |
| send_file traversal | High | `send_file\(.*request\|send_from_directory\(.*request` | Use `safe_join()`; validate filename |
| Zip slip | High | `zipfile\..*extract\(\|ZipFile.*extractall` | Check each entry name for `..` before extracting |
| Symlink attack | Medium | `os\.symlink\(\|os\.readlink\(` | Use `os.path.realpath()` and verify resolved path |
| Temp file race | Medium | `tempfile\.mktemp\(` | Use `tempfile.mkstemp()` or `NamedTemporaryFile` |
| shutil with user paths | High | `shutil\.(copy\|move\|rmtree)\(.*request` | Validate and resolve all paths before operations |

## 5. SSRF — Server-Side Request Forgery (CWE-918)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| requests with user URL | High | `requests\.(get\|post\|put\|delete\|head\|patch)\(.*request\.\|requests\.\w+\(.*user` | URL allowlist; block RFC1918 + link-local + metadata IPs |
| urllib user URL | High | `urllib\.request\.urlopen\(.*input\|urllib\.request\.Request\(.*user` | Same as above |
| aiohttp user URL | High | `aiohttp\.ClientSession.*\.get\(.*user\|session\.(get\|post).*request\.` | Validate + resolve DNS before request |
| httpx user URL | High | `httpx\.(get\|post\|AsyncClient).*user\|httpx\.\w+\(.*request\.` | URL allowlist; block internal ranges |
| Cloud metadata | Critical | `169\.254\.169\.254\|metadata\.google\|metadata\.azure` | Block metadata IPs in URL validation |

## 6. Cryptographic Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Insecure random | CWE-330 | High | `random\.(random\|randint\|choice\|randrange)\(.*token\|random\.\w+.*password\|random\.\w+.*secret\|random\.\w+.*key` | `secrets.token_hex()`, `secrets.token_urlsafe()` |
| Weak password hash | CWE-328 | Critical | `hashlib\.(md5\|sha1)\(.*password\|md5\(.*pass\|\.hexdigest\(\).*password` | Use `bcrypt`, `argon2`, or `scrypt` |
| Hardcoded secrets | CWE-798 | Critical | `(password\|secret\|api_key\|token\|private_key)\s*=\s*['"][^'"]{8,}` | Environment variables or secret manager |
| Timing attack | CWE-208 | High | `==.*hmac\|==.*digest\|==.*hash\|==.*token\|password\s*==` | `hmac.compare_digest(a, b)` |
| TLS verify disabled | CWE-295 | High | `verify\s*=\s*False\|CERT_NONE\|check_hostname\s*=\s*False` | Always `verify=True`; use cert bundles |
| ECB mode | CWE-327 | High | `MODE_ECB\|AES\.new\(.*ECB` | Use AES-GCM or AES-CBC with random IV |
| Static IV | CWE-329 | High | `iv\s*=\s*b['"]` | Generate random IV per encryption: `os.urandom(16)` |

## 7. Django Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| DEBUG in prod | CWE-215 | High | `DEBUG\s*=\s*True` | `DEBUG = False` in production; use env var |
| ALLOWED_HOSTS wildcard | CWE-16 | High | `ALLOWED_HOSTS\s*=\s*\['\*'\]` | Set explicit hostnames |
| SECRET_KEY hardcoded | CWE-798 | Critical | `SECRET_KEY\s*=\s*['"]` | Load from env: `os.environ['SECRET_KEY']` |
| CSRF disabled | CWE-352 | High | `@csrf_exempt\|csrf_exempt` | Remove; use CSRF tokens properly |
| No SSL redirect | CWE-319 | Medium | `SECURE_SSL_REDIRECT\s*=\s*False` | `SECURE_SSL_REDIRECT = True` |
| Unsafe redirect | CWE-601 | High | `HttpResponseRedirect\(.*request\.\|redirect\(.*request\.GET` | Validate redirect URL against allowlist |
| Session cookie insecure | CWE-614 | Medium | `SESSION_COOKIE_SECURE\s*=\s*False\|SESSION_COOKIE_HTTPONLY\s*=\s*False` | Set both to `True` |
| CORS misconfiguration | CWE-942 | High | `CORS_ALLOW_ALL_ORIGINS\s*=\s*True\|CORS_ORIGIN_ALLOW_ALL` | Set explicit `CORS_ALLOWED_ORIGINS` |
| Mass assignment | CWE-915 | Medium | `fields\s*=\s*'__all__'\|exclude\s*=\s*\[\]` | Explicit `fields = [...]` in forms/serializers |

## 8. Flask Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Debug mode prod | CWE-215 | High | `app\.run\(.*debug\s*=\s*True\|DEBUG\s*=\s*True` | `debug=False`; use env var |
| Hardcoded secret key | CWE-798 | Critical | `app\.secret_key\s*=\s*['"\|SECRET_KEY.*=\s*['"]` | `app.secret_key = os.environ[...]` |
| Autoescape off | CWE-79 | High | `autoescape\s*=\s*False\|Markup\(.*request` | Keep `autoescape=True` (Jinja2 default) |
| No CSRF protection | CWE-352 | High | `WTF_CSRF_ENABLED\s*=\s*False\|CSRFProtect` (missing) | Use Flask-WTF CSRFProtect |
| Unsafe file upload | CWE-434 | High | `request\.files.*save\(\|\.save\(.*filename` | `werkzeug.utils.secure_filename()`; validate type+size |

## 9. FastAPI Vulnerabilities

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing validation | CWE-20 | Medium | `def\s+\w+\(.*:\s*str[,)]` (raw str params without Pydantic) | Use Pydantic models with validators |
| CORS allow all | CWE-942 | High | `allow_origins\s*=\s*\["\*"\]\|allow_origins=\["` | Restrict to specific origins |
| Raw SQL in endpoint | CWE-89 | Critical | `\.execute\(.*f"\|text\(.*f"\|\.execute\(.*\.format` | Use ORM or parameterized queries |
| Response model leak | CWE-200 | Medium | `response_model\s*=\s*None\|exclude.*=\s*False` | Define explicit `response_model` with limited fields |

## 10. Async-Specific Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing await | CWE-691 | High | `if\s+check_\w+\((?!.*await)\|if\s+verify_\w+\((?!.*await)\|if\s+is_authorized\((?!.*await)` | Always `await` async security checks |
| Shared mutable state | CWE-362 | High | `global\s+\w+.*async\|shared_\w+\s*=\s*\{\}` | Use `asyncio.Lock()` or request-scoped state |
| Event loop blocking | CWE-400 | Medium | `time\.sleep\(\|\.read\(\).*async\s+def` | Use `await asyncio.sleep()` and async I/O |

## 11. XXE — XML External Entity (CWE-611)

| Source | Sev | Grep Pattern | Fix |
|--------|-----|-------------|-----|
| lxml/etree | High | `etree\.parse\(\|etree\.fromstring\(\|etree\.iterparse\(` | Use `defusedxml.lxml`; or `XMLParser(resolve_entities=False, no_network=True)` |
| minidom | High | `minidom\.parse\(\|minidom\.parseString\(` | Use `defusedxml.minidom` |
| SAX/pulldom | High | `sax\.parse\(\|pulldom\.parse\(` | Use `defusedxml.sax` / `defusedxml.pulldom` |
| expat | High | `xml\.parsers\.expat` | Use `defusedxml.expat` |
| xmlrpc | High | `xmlrpc\.client\|xmlrpc\.server` | Restrict methods; validate all inputs |

## 12. ReDoS — Regular Expression DoS (CWE-1333)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| User input in regex | High | `re\.compile\(.*request\|re\.compile\(.*user\|re\.search\(.*input.*,.*input` | Use `re.escape()` on user input; set timeout |
| Catastrophic backtracking | Medium | `\(\.\*\)\+\|\(\.\+\)\+\|\(\[^\\]\]\*\)\+` (nested quantifiers in patterns) | Avoid nested quantifiers; use atomic groups or `re2` |

## 13. File Upload Security (CWE-434)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| No type validation | High | `request\.files\[.*\.save\(` | Check MIME type + magic bytes; allowlist extensions |
| Path traversal in name | High | `\.filename.*open\(\|\.filename.*save\(` | `secure_filename()` + UUID rename |
| No size limit | Medium | `MAX_CONTENT_LENGTH` (missing) | Set `MAX_CONTENT_LENGTH` in Flask/Django |

## 14. Subprocess & Process Security (CWE-78)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| shell=True | Critical | `subprocess\.\w+\(.*shell\s*=\s*True` | Use arg list: `subprocess.run(["cmd", arg])` |
| os.system/popen | Critical | `os\.system\(\|os\.popen\(` | Replace with `subprocess.run([...])` |
| Env var injection | Medium | `env=.*request\|os\.environ\.update\(.*user` | Allowlist env vars; never pass user data directly |

## 15. Logging & Info Disclosure (CWE-532, CWE-209)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| Logging secrets | High | `log.*password\|log.*token\|log.*secret\|log.*api_key\|print\(.*password` | Redact sensitive fields; use structured logging |
| Stack traces exposed | Medium | `traceback\.format_exc\(\).*response\|traceback\.print_exc.*return` | Return generic errors; log details server-side |
| Debug endpoints | Medium | `@app\.route.*debug\|/debug/\|/admin.*debug` | Remove or protect with auth + IP restriction |

## 16. Type Safety Issues

| Vuln | CWE | Sev | Grep Pattern | Fix |
|------|-----|-----|-------------|-----|
| Missing type hints on auth | CWE-20 | Medium | `def\s+(authenticate\|authorize\|verify\|check_perms)\(.*\):\s*$` (no return type) | Add type hints; use `-> bool` or typed returns |
| Dynamic attr access | CWE-915 | High | `getattr\(.*request\|setattr\(.*request\|__getattr__.*user` | Allowlist attribute names; avoid dynamic access |
| Any type masking | CWE-20 | Low | `:\s*Any\s*[=,)]` in security modules | Use specific types; avoid `Any` on security boundaries |

## 17. JWT/Authentication (CWE-287)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| JWT verify disabled | Critical | `jwt\.decode\(.*verify=False\|jwt\.decode\(.*algorithms=\["none"\]\|jwt\.decode\((?!.*algorithms)` | Always verify JWT signatures. Pin algorithms: `jwt.decode(token, key, algorithms=["HS256"])` |
| Weak JWT secret | Critical | `SECRET_KEY.*=.*["'][a-z]\|JWT_SECRET.*=.*["']\|decode\(.*options=\{.*"verify_signature":\s*False` | Use strong secrets (32+ bytes). Set and validate expiration |

## 18. NoSQL Injection (CWE-943)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| pymongo user input | High | `pymongo.*find\(.*json\.loads\|pymongo.*find\(.*request\.\|collection\.(find\|update\|delete)\(.*\{.*user` | Validate and sanitize query operators. Never pass raw `json.loads(request.data)` to MongoDB queries |
| motor/MongoClient | High | `motor.*find\(.*request\.\|MongoClient.*\[.*request\.` | Strip `$` operators from user input |

## 19. Open Redirect (CWE-601)

| Vuln | Sev | Grep Pattern | Fix |
|------|-----|-------------|-----|
| Flask/Django redirect | Medium | `redirect\(.*request\.(args\|form\|GET\|POST)\|redirect\(.*url_for.*next\|HttpResponseRedirect\(.*request\.` | Validate redirect URLs are relative or on allowlisted domains. Use `url_has_allowed_host_and_scheme()` in Django |

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
