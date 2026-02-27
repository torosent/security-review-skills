# Dependency Scanning Workflows

## Detect Package Managers

Use glob to find manifest/lock files:

```
**/package-lock.json, **/yarn.lock, **/pnpm-lock.yaml    # Node.js
**/requirements.txt, **/Pipfile.lock, **/poetry.lock      # Python
**/go.sum, **/go.mod                                       # Go
**/*.csproj, **/packages.lock.json, **/Directory.Packages.props  # .NET
```

## Audit Commands (via bash)

### Node.js
```bash
npm audit --json 2>/dev/null | head -100
# Or for yarn:
yarn audit --json 2>/dev/null | head -50
```

### Python
```bash
pip audit --format json 2>/dev/null || pip-audit --format json 2>/dev/null
# Fallback: check against known vulns
pip list --outdated --format json 2>/dev/null
```

### Go
```bash
go list -m -json all 2>/dev/null | head -100
govulncheck ./... 2>/dev/null
```

### .NET
```bash
dotnet list package --vulnerable --format json 2>/dev/null
```

## Manual Checks (When Audit Tools Unavailable)

1. **Read lock files** — check package versions against known CVE databases
2. **Flag outdated major versions** — old major versions likely have unpatched vulns
3. **Check for deprecated packages** — unmaintained packages are high risk
4. **Flag pinned-to-old versions** — `"lodash": "3.x"` when current is `4.x`

## Red Flags in Dependencies

| Pattern | Risk |
|---------|------|
| `"*"` or `"latest"` as version | Unpinned — could pull malicious version |
| Very low download count | Potential typosquatting |
| No lock file present | Non-deterministic builds |
| Lock file in `.gitignore` | Supply chain risk |
| `postinstall` scripts | Arbitrary code execution on install |
| `node-pre-gyp` + `binary` URLs | Binary substitution attacks |

## Severity Mapping

- **Critical**: Known RCE/deserialization CVE in direct dependency
- **High**: Known auth bypass, SSRF, or injection CVE
- **Medium**: Known XSS, DoS, or info disclosure CVE
- **Low**: Outdated but no known active CVE
