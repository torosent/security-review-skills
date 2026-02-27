---
name: security-review
description: >
  Comprehensive AI-powered security review agent for polyglot codebases and infrastructure.
  USE FOR: Security audits, vulnerability scanning, secrets detection, dependency auditing,
  IaC security review, compliance mapping (SOC2/HIPAA/PCI-DSS), OWASP Top 10 and CWE/SANS Top 25
  analysis across JavaScript/TypeScript, Python, C#/.NET, and Go codebases with Docker, Kubernetes,
  Terraform, Bicep, and Helm infrastructure.
  DO NOT USE FOR: General code review (style, formatting), performance optimization, or functional testing.
---

# Security Review Agent

Performs deep, multi-pass security analysis of code and infrastructure with structured findings.

## When to Use This Skill

- User asks for a security review, audit, or vulnerability scan
- User mentions OWASP, CWE, CVE, secrets, credentials, or compliance
- User wants to check code or infrastructure for security issues
- Before deploying to production or merging security-sensitive changes
- Compliance readiness checks (SOC2, HIPAA, PCI-DSS)

## Quick Reference

| Capability | Description |
|---|---|
| Languages | JavaScript/TypeScript, Python, C#/.NET, Go |
| Infrastructure | Dockerfile, Kubernetes, Terraform, Bicep, Helm |
| Frameworks | OWASP Top 10, CWE/SANS Top 25, SOC2, HIPAA, PCI-DSS |
| Tools Used | grep, glob, bash, view (built-in Copilot CLI tools) |

## Multi-Pass Security Review Workflow

Execute these passes sequentially. Report findings with severity (Critical/High/Medium/Low/Info), CWE ID, file location, and remediation.

### Pass 1: Secrets & Credentials Scan
Scan for hardcoded secrets, API keys, tokens, and credentials.
See [secrets detection patterns](references/secrets-detection.md).

### Pass 2: Dependency Vulnerability Audit
Check lock files and manifests for known vulnerable dependencies.
See [dependency scanning workflows](references/dependency-scanning.md).

### Pass 3: Code Vulnerability Analysis
Analyze source code for OWASP Top 10 and CWE/SANS Top 25 vulnerabilities.
See [OWASP Top 10](references/owasp-top-10.md) | [CWE/SANS Top 25](references/cwe-sans-top-25.md).

Language-specific deep analysis:
- [JavaScript/TypeScript](references/language-specific/javascript.md)
- [Python](references/language-specific/python.md)
- [C#/.NET](references/language-specific/csharp.md)
- [Go](references/language-specific/golang.md)

### Pass 4: Infrastructure Security Review
Scan IaC files for misconfigurations and insecure defaults.
See [IaC security checks](references/iac-security.md).

### Pass 5: Compliance Mapping
Map all findings to applicable compliance frameworks.
See [compliance frameworks](references/compliance-frameworks.md).

## Findings Format

For each finding, report:

```
[SEVERITY] CWE-XXX: Title
File: path/to/file.ext:line
Description: What was found
Impact: What could happen
Remediation: How to fix it
Compliance: Affected frameworks (if applicable)
```

## Severity Classification

See [severity scoring guide](references/severity-scoring.md) for classification criteria.

## Secure Coding Patterns

See [secure patterns](references/secure-patterns.md) for recommended fixes and alternatives.

## Rules

1. **Always run all 5 passes** — do not skip passes even if early passes find no issues
2. **Use grep/glob for pattern scanning** — search broadly, then verify with view
3. **Never report style issues** — only genuine security vulnerabilities
4. **Include CWE IDs** for all code-level findings
5. **Provide actionable remediation** — show the fix, not just the problem
6. **Rate severity honestly** — do not inflate or deflate findings
7. **Check both source and config files** — vulnerabilities hide in configuration
8. **Detect language/framework automatically** from file extensions and manifests
