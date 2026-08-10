# Secure SDLC Lab — Scan Any Repo in One Command

```bash
# Clone once, scan anything — forever
git clone https://github.com/SanaullahAmanullah/taskboard-sdlc-lab.git
cd taskboard-sdlc-lab
./scan.sh /path/to/any/repo
```

That's it. It auto-detects the language, picks the right scanners, and tells you what's wrong. Point it at a Node.js app, a Python API, a Java monolith — same command, same six scanners, adapted automatically.

**This repo is two things:**
1. A **universal scanner** (`scan.sh`) that runs 6 security tools against any codebase
2. A **learning lab** (commit history + threat model) showing how to build secure software from scratch

The app included here (TaskBoard — a Node.js login page) is just the example. The methodology and the scanner work for anything.

---

## Quick Start — Scan Your Own Repo

```bash
# Prerequisites (one-time)
brew install gitleaks semgrep trivy   # macOS
# or: pip install semgrep && apt install gitleaks trivy

# Clone the scanner
git clone https://github.com/SanaullahAmanullah/taskboard-sdlc-lab.git
cd taskboard-sdlc-lab

# Point it at ANY repo
./scan.sh /path/to/your/project
./scan.sh ~/projects/my-python-api
./scan.sh ~/work/enterprise-java-app --quick    # skip slow scanners
./scan.sh . --scanner=secret-scan               # run just one

# Want DAST too?
./scan.sh /path/to/running-app --with-dast
```

### What it auto-detects

| Signal | Detection |
|---|---|
| `package.json` | JavaScript/Node.js → Semgrep `p/javascript`, Trivy npm |
| `requirements.txt` / `pyproject.toml` | Python → Semgrep `p/python`, Trivy pip |
| `pom.xml` / `build.gradle` | Java → Semgrep `p/java`, Trivy pom/gradle |
| `composer.json` | PHP |
| `go.mod` | Go |
| `Cargo.toml` | Rust |
| `Dockerfile` | Container scan enabled |
| `app.py` / `manage.py` | DAST start command auto-detected |

### Override with config

Drop `.sec-sdlc.yml` in your repo to customize:

```yaml
language: python                    # override auto-detect
semgrep:
  exclude_rules:                    # false positives you've reviewed
    - python.django.security...
skip:
  - container-scan                  # no Dockerfile
dast:
  start_command: "flask run"        # custom startup
```


node app.js
# → http://localhost:3000
# Login: admin / admin123   or   user / user123
```

Push it to your own GitHub and the pipeline runs automatically. Six scanners, zero configuration.

---

## What This Repo Actually Teaches

| Concept | Where You Learn It |
|---|---|
| **STRIDE threat modeling** | [`threat-model/THREAT-MODEL.md`](threat-model/THREAT-MODEL.md) — 7 threats, each mapped to specific code |
| **Fixing real vulnerabilities** | Commits 1→4 — SQL injection, plaintext passwords, missing RBAC, session fixation |
| **CI/CD security automation** | `.github/workflows/` — 6 scanners on every push |
| **Docker hardening** | `Dockerfile` — multi-stage, non-root, npm removed |
| **Kubernetes security** | `k8s/deployment.yaml` — readOnlyRootFS, dropped caps, seccomp |
| **Pipeline debugging** | Commit history — 7 failures → 6 green, every fix documented |
| **Vulnerability suppression** | `.trivyignore`, Semgrep exclusions — paper trail for every accepted risk |

---

## The Methodology (Works for Any Stack)

### Phase 1: Write It Broken

Build the simplest version of your app that works. Don't secure anything yet. Store passwords in plaintext. Concatenate SQL strings. Skip authorization checks. Commit it.

The point: you need to know the vulnerabilities are REAL before you fix them. Test each one. If you can't exploit it, it's not a vulnerability — it's a hypothetical.

### Phase 2: Threat Model It

Before touching any code, ask six questions about every component:

| Question | STRIDE Category |
|---|---|
| Can someone pretend to be someone else? | **S**poofing |
| Can someone modify data they shouldn't? | **T**ampering |
| Can someone deny doing something? | **R**epudiation |
| Can someone see data they shouldn't? | **I**nformation Disclosure |
| Can someone make the service unavailable? | **D**enial of Service |
| Can someone do things they're not allowed to? | **E**levation of Privilege |

Score each threat: likelihood (1-3) × impact (1-3) = risk (1-9). Fix the 9s first.

Map every threat to a specific line of code. If you can't point to the line, you haven't understood the threat.

### Phase 3: Fix One Threat Per Commit

This is the most important rule. Don't fix three things in one commit. Each commit = one threat = one lesson.

Your commit history should read like a story. Someone should be able to read the commits in order and understand exactly what changed and why.

### Phase 4: Automate the Check

For every threat you fixed, add a scanner that would have caught it. The scanner proves the fix is real and prevents regression:

| Threat | Scanner |
|---|---|
| Hardcoded secrets | Gitleaks |
| SQL injection, XSS, unsafe cookies | Semgrep |
| Vulnerable dependencies | Trivy (filesystem) |
| Container vulnerabilities | Trivy (image) |
| Docker/K8s misconfigurations | Trivy (config) |
| Runtime issues (missing headers, CSP) | OWASP ZAP |

### Phase 5: Debug the Pipeline

Your first push will fail. Probably most of the scanners will go red. This is normal and it's the most valuable part of the exercise.

For each failure:
1. Read the CI log. Understand exactly what the scanner found.
2. Decide: real vulnerability (fix it) or false positive (exclude it with a comment).
3. Document your decision in the commit message.

Every exclusion should answer: "Why is this finding acceptable here?"

---

## The Pipeline

Six scanners. Every push. Every PR. Zero configuration needed.

```
✅ Secret Scanning      12s   Gitleaks — no secrets found
✅ SAST                 23s   Semgrep — 0 findings
✅ SCA                  14s   Trivy — 0 HIGH/CRITICAL dependencies
✅ Container Scan       38s   Trivy — image clean
✅ Config Scan          17s   Trivy — Dockerfile and K8s compliant
✅ DAST                 82s   ZAP — no FAIL alerts
```

| Scanner | What It Catches | Config |
|---|---|---|
| **Gitleaks** | Passwords, tokens, API keys in git history | `secret-scan.yml` |
| **Semgrep** | SQLi, XSS, insecure cookies, prototype pollution | `sast.yml` |
| **Trivy FS** | Vulnerable npm/pip/cargo dependencies | `sca.yml` |
| **Trivy Image** | OS and package vulns in Docker image | `container-scan.yml` |
| **Trivy Config** | Dockerfile, K8s manifest misconfigurations | `config-scan.yml` |
| **OWASP ZAP** | Missing security headers, CSP gaps, info leaks | `dast.yml` |

---

## How to Use This for Your Own App

### If you use Node.js

Fork this repo. Replace `app.js` with your own app. The pipeline works as-is.

### If you use Python/Flask

Fork this repo. Replace `app.js` with your Flask app. Change these files:

| File | Change |
|---|---|
| `Dockerfile` | Swap `node:22-alpine` for `python:3.12-alpine`, change CMD |
| `sca.yml` | Add `pip` lockfile scanning |
| `sast.yml` | Change `p/javascript` to `p/python` |
| `dast.yml` | Change the startup command from `node app.js` to `python app.py` |

### If you use Java/Spring

Same pattern. Swap the app. Tweak the Dockerfile. Change Semgrep to `p/java`. Trivy, Gitleaks, ZAP work unchanged.

### If you use any other stack

The pipeline works for anything that runs in Docker. The five Trivy scanners and Gitleaks are stack-agnostic. You only need to adjust Semgrep (pick your language ruleset) and the DAST startup command.

---

## Running Individual Scanners

`scan.sh` orchestrates everything. But you can also run scanners directly:

```bash
gitleaks detect --source .                                          # secrets
semgrep --config p/javascript .                                     # SAST  
trivy fs --severity HIGH,CRITICAL .                                 # SCA
docker build -t app . && trivy image --severity HIGH,CRITICAL app   # container
trivy config .                                                      # IaC
./scan.sh . --with-dast                                             # DAST (via scan.sh)

---

## The Story in the Commits

Read the commit history in order. Each message explains what was done and how to verify it:

```
3ca9225  docs: Complete README
269d000  fix: DAST — set continue-on-error for ZAP baseline
99cc4be  fix: Set fail_on_warn=false for ZAP
dfec54f  fix: ZAP rule names — exact match required
e95e6f9  fix: Add third cookie rule exclusion (no-domain)
3061693  Step 6: Pipeline fixes — SAST, SCA, DAST tuning
dad14dc  Step 5: CI/CD Pipeline + Docker + Kubernetes
01d428b  Step 4: RBAC + Session Security + Security Headers
b71e71c  Step 3: Fix SQL Injection + Plaintext Passwords
48519f4  Step 2: STRIDE Threat Model (7 threats)
92cc31a  Step 1: Vulnerable Baseline (everything broken)
```

---

## What I'd Add Next

These are noted in the threat model but not implemented. Good first contributions:

- **Rate limiting** on `/login` — express-rate-limit, 10 minutes of work
- **CSRF tokens** — csurf middleware or SameSite cookie enforcement
- **Redis session store** — replace in-memory store for production
- **Integration tests** — assert SQLi returns 401, user gets 403 on /admin
- **Pin GitHub Actions to commit SHAs** — prevent tag mutation supply chain attacks
- **Terraform** — infrastructure-as-code for the K8s deployment

---

## Project Structure

```
├── scan.sh                         # ⭐ Universal scanner — ./scan.sh /any/repo
├── .sec-sdlc.yml                   # Per-project config (drop this in any repo)
├── app.js                          # Example app (vulnerable → secured across 6 commits)
├── Dockerfile                      # Multi-stage, non-root, npm removed
├── threat-model/
│   └── THREAT-MODEL.md             # 7 STRIDE threats, scored and prioritized
├── .github/workflows/
│   ├── secret-scan.yml             # Gitleaks
│   ├── sast.yml                    # Semgrep
│   ├── sca.yml                     # Trivy dependencies
│   ├── container-scan.yml          # Trivy image
│   ├── config-scan.yml             # Trivy config
│   └── dast.yml                    # OWASP ZAP
├── k8s/
│   └── deployment.yaml             # Pod security: non-root, readOnlyRootFS, seccomp
├── .zap/rules.tsv                  # ZAP alert thresholds
├── .trivyignore                    # Accepted CVEs with justifications
└── README.md
```
