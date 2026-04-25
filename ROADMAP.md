# 🛡️ SecretSentry — Vulnerability Scanning Roadmap

A phased plan to evolve SecretSentry from a secret scanner into a full code security scanner.

```
Phase 1: Dependency CVEs          ← Highest ROI, easiest
  ↓
Phase 2: Code Pattern Vulns       ← Natural extension of current pipeline
  ↓
Phase 3: Config Vulnerabilities   ← Reuses existing file scanning infra
  ↓
Phase 4: SAST-Lite with AST       ← Big complexity jump
  ↓
Phase 5: Supply Chain & License   ← Nice to have
```

---

## Phase 1: Dependency Vulnerabilities

Scan lock/manifest files and check for known CVEs. Quickest win — can ship in a day.

### Scope

| Target File | Ecosystem |
|-------------|-----------|
| `package.json` / `package-lock.json` / `yarn.lock` | npm |
| `requirements.txt` / `Pipfile.lock` / `poetry.lock` | Python |
| `build.gradle` / `build.gradle.kts` | Android / Java |
| `pom.xml` | Maven / Java |
| `go.sum` | Go |
| `Gemfile.lock` | Ruby |
| `Cargo.lock` | Rust |

### Approach

- Parse dependency files to extract package names + versions
- Query [OSV.dev API](https://osv.dev/) (free, no auth, covers all ecosystems)
- Fallback: [NVD API](https://nvd.nist.gov/developers/vulnerabilities) for broader CVE data
- No new dependencies needed — just HTTP requests via `urllib`

### New Tool

```
scan_dependencies(filepath_or_dirpath)
```

### Output

| Package | Version | CVE | Severity | CVSS | Fix Version | Description |
|---------|---------|-----|----------|------|-------------|-------------|
| lodash | 4.17.15 | CVE-2020-8203 | HIGH | 7.4 | 4.17.19 | Prototype pollution |

### Effort: Low-Medium (2-3 days)

---

## Phase 2: Code Pattern Vulnerabilities

Detect common insecure coding patterns via regex + pipeline rules. Fits naturally into the existing 6-stage architecture as a new stage.

### Patterns to Detect

| Vulnerability | Pattern | Languages | Severity |
|---------------|---------|-----------|----------|
| SQL Injection | String concat in SQL queries | Python, Java, JS | CRITICAL |
| XSS | `innerHTML`, `dangerouslySetInnerHTML`, unescaped template vars | JS, HTML | HIGH |
| Command Injection | `os.system()`, `subprocess(shell=True)`, `exec()` with input | Python, JS, Java | CRITICAL |
| Path Traversal | `../` in file ops, unsanitized params in file paths | All | HIGH |
| Insecure Deserialization | `pickle.loads()`, `yaml.load()` without SafeLoader | Python, Java | HIGH |
| Weak Crypto | MD5/SHA1 for passwords, DES, ECB mode, `Math.random()` for security | All | MEDIUM |
| Hardcoded HTTP | `http://` in production URLs (not localhost) | All | MEDIUM |
| Insecure Permissions | `chmod 777`, `0o777`, world-readable files | Python, Shell | MEDIUM |
| Debug Left On | `DEBUG = True`, `console.log(password)` | Python, JS, Java | LOW |
| Missing Auth | Routes without auth middleware | Express, Flask, Django | HIGH |
| Open Redirect | Unvalidated redirect URLs from user input | JS, Python | MEDIUM |
| SSRF | User-controlled URLs in HTTP requests | Python, JS, Java | HIGH |
| XXE | XML parsing without disabling external entities | Java, Python | HIGH |
| CORS Misconfiguration | `Access-Control-Allow-Origin: *` with credentials | JS, Python | MEDIUM |
| Timing Attack | Non-constant-time string comparison for secrets | All | MEDIUM |

### Implementation

- New pipeline stage: `stages/vuln_patterns.py`
- Reuses existing confidence scoring engine
- Each pattern gets a base score, adjusted by context (test file, comment, etc.)

### New Tool

```
scan_vulnerabilities(code, filename)
```

### Effort: Medium (1-2 weeks)

---

## Phase 3: Configuration Vulnerabilities

Scan config files for insecure settings. Reuses existing file scanning infrastructure.

### Targets

| Config File | What to Check |
|-------------|---------------|
| `Dockerfile` | Running as root, `latest` tag, `ADD` vs `COPY`, exposed ports, secrets in `ENV` |
| `docker-compose.yml` | Privileged mode, host network, mounted sensitive paths (`/etc`, `/var/run/docker.sock`) |
| `nginx.conf` | Missing security headers, SSL misconfig, directory listing, server version exposed |
| `AndroidManifest.xml` | `debuggable=true`, `allowBackup=true`, exported components without permissions |
| `.github/workflows/*.yml` | `pull_request_target` + checkout (pwn request), secrets in logs, `actions/checkout` without pinning |
| `terraform/*.tf` | Public S3 buckets, open security groups (0.0.0.0/0), unencrypted resources, overly permissive IAM |
| `kubernetes/*.yaml` | Privileged containers, no resource limits, default service accounts, hostPath mounts |
| `serverless.yml` | Overly permissive IAM roles, public API endpoints without auth |
| `.env.example` | Real secrets accidentally left in example files |

### New Tool

```
scan_config(filepath)
```

### Effort: Medium (1-2 weeks)

---

## Phase 4: SAST-Lite with AST

Move beyond regex to actual code understanding. This is the biggest complexity jump.

### Capabilities

| Capability | How | Effort |
|------------|-----|--------|
| AST parsing | `tree-sitter` + `py-tree-sitter` for Python, JS, Java, Go, Kotlin | High |
| Basic taint tracking | Track user input → dangerous sink (SQL, exec, file ops) | High |
| Scope-aware analysis | Know if a variable is local, parameter, or global | Medium |
| Import resolution | Know what `from crypto import ...` actually imports | Medium |
| Data flow (intra-function) | Follow variable assignments within a function | High |
| Cross-function tracking | Follow data across function calls (limited) | Very High |

### What This Enables

- Distinguish `password = getenv("PWD")` (safe) from `password = "hunter2"` (not safe)
- Track user input from `request.params` through to `db.query()`
- Understand that `hashlib.md5(password)` is weak but `hashlib.sha256(data)` for checksums is fine
- Reduce false positives by understanding code context

### Dependencies

- `tree-sitter` — multi-language AST parser
- Language grammars: `tree-sitter-python`, `tree-sitter-javascript`, etc.

### New Tool

```
analyze_code(filepath)  # Deep AST-based analysis
```

### Effort: High (3-6 weeks)

---

## Phase 5: Supply Chain & License

Dependency health and compliance checks.

| Check | How |
|-------|-----|
| Typosquatting | Compare dependency names against popular packages (Levenshtein distance) |
| License compliance | Parse license fields, flag GPL in commercial projects |
| Outdated dependencies | Check latest version vs installed version |
| Deprecated packages | Check if package is archived/unmaintained on GitHub/PyPI/npm |
| Maintainer reputation | Check download counts, last publish date, contributor count |

### New Tool

```
scan_supply_chain(dirpath)
```

### Effort: Medium (1-2 weeks)

---

## Tool Summary

| Phase | New Tool | What It Does |
|-------|----------|-------------|
| 1 | `scan_dependencies` | Check lock/manifest files for known CVEs |
| 2 | `scan_vulnerabilities` | Detect insecure code patterns (SQLi, XSS, etc.) |
| 3 | `scan_config` | Check config files for misconfigurations |
| 4 | `analyze_code` | AST-based deep code analysis |
| 5 | `scan_supply_chain` | Dependency health + license compliance |

All tools follow the same tabular output format with confidence scoring.

---

## Architecture Evolution

```
Current (v0.1):
  server.py → pipeline.py → 6 stages → findings

Phase 1-3 (v0.2):
  server.py → pipeline.py → 6 stages (secrets)
                           → dependency scanner
                           → vuln pattern stage
                           → config scanner
                           → unified findings

Phase 4-5 (v0.3):
  server.py → pipeline.py → 6 stages (secrets)
                           → AST engine (tree-sitter)
                           → taint tracker
                           → dependency scanner
                           → supply chain checker
                           → unified findings with cross-stage correlation
```

---

## Priority Matrix

| Phase | Impact | Effort | Dependencies | Ship Target |
|-------|--------|--------|-------------|-------------|
| 1 — Dependency CVEs | 🔴 High | 🟢 Low | None (stdlib HTTP) | Week 1 |
| 2 — Code Patterns | 🔴 High | 🟡 Medium | None | Week 2-3 |
| 3 — Config Vulns | 🟡 Medium | 🟡 Medium | None | Week 4-5 |
| 4 — AST/SAST | 🔴 High | 🔴 High | tree-sitter | Week 6-12 |
| 5 — Supply Chain | 🟢 Low | 🟡 Medium | None | Week 13+ |
