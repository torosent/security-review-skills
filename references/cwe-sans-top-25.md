# CWE/SANS Top 25 — Most Dangerous Software Weaknesses

## Memory & Buffer

| CWE | Name | Grep Pattern |
|-----|------|-------------|
| CWE-787 | Out-of-bounds Write | `unsafe\.\|Buffer\.alloc\(.*\)\|memcpy\|strcpy\|strcat` |
| CWE-125 | Out-of-bounds Read | `\[.*\]\s*//.*no.*bound\|buffer\[.*len` |
| CWE-416 | Use After Free | `free\(.*\).*\n.*->` (C/C++ only) |
| CWE-190 | Integer Overflow | `int\b.*\*\|uint.*\+.*uint\|math\.MaxInt` |

## Injection

| CWE | Name | Grep Pattern |
|-----|------|-------------|
| CWE-89 | SQL Injection | `\.query\(.*\+\|\.query\(.*\$\{.*\}\|string\.Format.*SELECT\|f".*SELECT` |
| CWE-78 | OS Command Injection | `exec\(\|system\(\|popen\(\|subprocess.*shell=True\|child_process\.exec` |
| CWE-79 | Cross-site Scripting | `innerHTML\|dangerouslySetInnerHTML\|v-html\|\|htmlSafe\|\.write\(` |
| CWE-77 | Command Injection | `Runtime\.getRuntime\|ProcessBuilder\|os/exec.*\+` |

## Authentication & Access

| CWE | Name | Grep Pattern |
|-----|------|-------------|
| CWE-306 | Missing Authentication | `@AllowAnonymous\|skipAuth\|noAuth\|public.*endpoint` |
| CWE-862 | Missing Authorization | `@PermitAll\|authorize.*false\|rbac.*skip` |
| CWE-863 | Incorrect Authorization | `role.*==.*"user".*admin\|isAdmin.*=.*req\.` |
| CWE-798 | Hard-coded Credentials | `password\s*=\s*["']\|api_key\s*=\s*["']\|secret\s*=\s*["']` |

## Data & Crypto

| CWE | Name | Grep Pattern |
|-----|------|-------------|
| CWE-22 | Path Traversal | `\.\.\/\|\.\.\\\\.*open\|path\.join.*req\.\|filepath\.Join.*param` |
| CWE-434 | Unrestricted Upload | `multer\|FileUpload\|enctype.*multipart\|Content-Type.*boundary` |
| CWE-502 | Deserialization | `pickle\.load\|yaml\.load\(\|readObject\|BinaryFormatter\|JsonConvert.*TypeNameHandling` |
| CWE-611 | XXE | `XMLParser\|DocumentBuilder\|etree\.parse\|xml\.NewDecoder\|XmlReader` |

## Logic & Design

| CWE | Name | Grep Pattern |
|-----|------|-------------|
| CWE-476 | NULL Pointer Deref | `\.Length\|\.length\|\.Count\|\.size\(\)` (without null check) |
| CWE-20 | Improper Validation | `parseInt\(.*req\.\|Number\(.*input\|int\(.*request\.\|strconv\.Atoi.*param` |
| CWE-352 | CSRF | `csrf.*disable\|csrf.*false\|@IgnoreAntiforgery\|exempt.*csrf` |
| CWE-362 | Race Condition | `go\s+func\|threading\.Thread\|Task\.Run\|Promise\.all.*write` |
