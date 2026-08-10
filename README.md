# Secure SDLC Lab — Built from Scratch

**Learning project: building a secure application and CI/CD pipeline, one commit at a time.** Each step starts vulnerable, then applies a security fix. The threat model drives the work — not the other way around.

---

## The Approach

Instead of reading about Secure SDLC, you build it:

1. **Write vulnerable code first** — plaintext passwords, no auth, SQL injection
2. **Threat model it** — STRIDE: what could go wrong?
3. **Fix one threat at a time** — each commit addresses one finding
4. **Automate the check** — add a CI/CD scanner that catches regression
5. **Ship the fixed version** — PR passes all checks, merge to main

Every commit is a lesson. The commit history tells the story: threat → fix → verify.

---

## The Application

**TaskBoard** — a simple Node.js/Express task management app with SQLite.

- Users can log in, view tasks, and (if admin) manage users
- Intentionally simple — the complexity is in the security pipeline, not the app

---

## Learning Path — 10 Steps

| Step | What You Build | Security Concept |
|---|---|---|
| **1** | Basic app — login, tasks, SQLite | Baseline. Everything is broken on purpose |
| **2** | Threat model (STRIDE) | How to think about what could go wrong BEFORE coding |
| **3** | Fix: Password hashing (bcrypt) | Defense in depth. Plaintext → hash |
| **4** | Fix: SQL injection (parameterized queries) | Never trust user input |
| **5** | Fix: Session security (HttpOnly, regeneration) | Cookie attributes, session fixation |
| **6** | Fix: RBAC (admin vs user routes) | Authorization ≠ Authentication |
| **7** | Fix: Security headers (Helmet, CSP) | HTTP-layer defense |
| **8** | CI/CD Pipeline — Gitleaks, Semgrep, Trivy, ZAP | Automate every check |
| **9** | Docker — multi-stage, non-root, minimal image | Container security |
| **10** | Kubernetes — pod security, seccomp, capabilities | Orchestration security |

---

## How to Use This Repo

### Run the app

```bash
npm install
export SESSION_SECRET="your-random-secret-here"
node app.js
# Open http://localhost:3000
```

### Default users

| Username | Password | Role |
|---|---|---|
| admin | admin123 | admin |
| user | user123 | user |

### Run security checks locally

```bash
# Secret scanning
gitleaks detect --source .

# SAST
semgrep --config p/javascript .

# SCA
trivy fs --severity HIGH,CRITICAL .

# Container scan
docker build -t taskboard .
trivy image --severity HIGH,CRITICAL taskboard
```

---

## Pipeline

Every push and PR runs:

| Scanner | What It Catches |
|---|---|
| **Gitleaks** | Hardcoded secrets, tokens, passwords |
| **Semgrep** | SQL injection, XSS, insecure cookies, prototype pollution |
| **Trivy (FS)** | Vulnerable dependencies (HIGH/CRITICAL) |
| **Trivy (Image)** | Vulnerabilities in the Docker image |
| **Trivy (Config)** | Dockerfile and K8s misconfigurations |
| **OWASP ZAP** | Runtime vulnerabilities (XSS, injection, misconfig) |

---

## What I Learned

*This section fills in as I build each step.*

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Semgrep Rules](https://semgrep.dev/r)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
