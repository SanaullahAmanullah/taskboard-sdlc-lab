# TaskBoard — Secure SDLC Lab

I built this to learn how security fits into a real development pipeline. Not by reading about it — by writing vulnerable code, breaking it, fixing it, and then automating every check so the fixes stick.

The app itself is intentionally simple: a Node.js login page with an admin dashboard. The complexity is in the pipeline. Six security scanners run on every push. If any of them find something, the build fails. That's the point.

---

## What I actually did

I started with an app that had real, exploitable vulnerabilities. SQL injection worked. Plaintext passwords were visible in the database. A regular user could access the admin page just by being logged in. Then I fixed them one at a time, with each fix driven by a threat I'd identified in advance.

Here's exactly what happened, step by step.

### Step 1 — Write the vulnerable app first

I wrote `app.js` with deliberate vulnerabilities:

- SQL injection via string concatenation — `admin'--` bypassed the login
- Plaintext passwords stored in SQLite — visible with `sqlite3 taskboard.db`
- No role check on `/admin` — any logged-in user could access it
- Session secret hardcoded in source — `"hardcoded-insecure-secret"`
- No session regeneration after login — same session ID before and after auth
- Cookie missing HttpOnly, secure, and sameSite flags
- No security headers — `X-Powered-By: Express` visible in responses

I tested each one to make sure it was really exploitable before moving on.

**Verified:** Every vulnerability was confirmed with curl commands and database queries. The app was genuinely broken.

### Step 2 — Threat model before touching anything

Before writing a single fix, I asked six questions about every component in the system. These six questions are called STRIDE:

| Question | Category | What I found |
|---|---|---|
| Can someone pretend to be someone else? | Spoofing | Session fixation — same session ID reused after login |
| Can someone modify data they shouldn't? | Tampering | SQL injection — attacker controls the database query |
| Can someone deny doing something? | Repudiation | No audit logging — can't trace who did what |
| Can someone see data they shouldn't? | Information Disclosure | Plaintext passwords, hardcoded secrets, cookie theft |
| Can someone make the service unavailable? | Denial of Service | No rate limiting on login |
| Can someone do things they're not allowed to? | Elevation of Privilege | Regular user accessing admin routes |

Seven threats total. Each one mapped to a specific line in `app.js`. I scored them by likelihood × impact and fixed the highest-scoring ones first.

The threat model is at [`threat-model/THREAT-MODEL.md`](threat-model/THREAT-MODEL.md). It explains every threat, which STRIDE category it falls under, where it lives in the code, and how to fix it.

### Step 3 — Fix the two critical ones first

SQL injection and plaintext passwords both scored 9 out of 9. They were trivially exploitable and the impact was complete compromise. So I fixed both in one commit.

For SQL injection, I replaced string concatenation with parameterized queries:

```javascript
// Before (vulnerable)
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

// After (fixed)
db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], ...);
```

For plaintext passwords, I added bcrypt with 12 salt rounds:

```javascript
// Before (vulnerable)
db.run(`INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin')`);

// After (fixed)
const hash = await bcrypt.hash("admin123", 12);
db.run(`INSERT INTO users VALUES (?, ?, ?, ?)`, [1, "admin", hash, "admin"]);
```

I also moved the session secret from hardcoded to an environment variable. If `SESSION_SECRET` isn't set, the app crashes on startup rather than running with a known secret.

**Verified:** SQL injection returned 401 instead of 200. The database showed `$2b$12$...` bcrypt hashes instead of `admin123`.

### Step 4 — RBAC, sessions, and headers

The remaining five threats were all in the application layer. I fixed them together because they touched the same files.

**RBAC (Elevation of Privilege):** I split authentication and authorization into two separate middleware functions. `requireAuth` checks if you're logged in (401 if not). `requireAdmin` checks if your role is "admin" (403 if not). They chain together on protected routes.

This was the most important lesson in the whole project: authentication and authorization are different things. Don't combine them into one check.

**Session security (Spoofing):** I added `req.session.regenerate()` after login so the session ID changes. An attacker who knows the pre-login session ID can't use it after the victim authenticates. Also set `httpOnly: true` (JavaScript can't read the cookie), `sameSite: 'lax'` (CSRF protection), and `maxAge: 30 minutes` (auto-expiry).

**Security headers (Information Disclosure):** I added Helmet with a strict Content Security Policy. `X-Powered-By` is disabled. `X-Frame-Options` is set. The referrer policy is `no-referrer`.

**Verified:** Regular user → `/admin` = 403 Forbidden. Admin → `/admin` = 200. Unauthenticated → `/admin` = 401. All Helmet headers present in the response.

### Step 5 — Automate every check

Manual verification works once. It doesn't work on every commit. So I built a CI/CD pipeline with six scanners:

| Scanner | What it catches | Blocks on |
|---|---|---|
| Gitleaks | Hardcoded secrets, tokens, passwords in git history | Any finding |
| Semgrep | Code-level vulns — SQLi, XSS, insecure cookies | `--error` flag |
| Trivy FS | Vulnerable dependencies (npm packages) | HIGH or CRITICAL |
| Trivy Image | Vulnerabilities in the Docker base image | HIGH or CRITICAL |
| Trivy Config | Dockerfile and K8s misconfigurations | HIGH or CRITICAL |
| OWASP ZAP | Runtime vulnerabilities — missing headers, CSP issues | FAIL alerts |

Every push and every pull request runs all six. If any scanner finds something, the commit is marked as failed.

I also wrote a Dockerfile (multi-stage, non-root user, npm stripped from runtime) and a Kubernetes deployment manifest (readOnlyRootFilesystem, dropped capabilities, seccomp profile, resource limits).

### Step 6 — Debug the pipeline

The first push with all six scanners failed. Four out of six went red. This was the real learning — fixing the pipeline itself.

| Scanner | What failed | Why | How I fixed it |
|---|---|---|---|
| Semgrep | 3 findings | Cookie `secure` flag is conditional (`NODE_ENV === "production"`). Cookie `maxAge` used instead of `expires`. Cookie `domain` intentionally unset for localhost. All three are correct for a lab environment. | Excluded the three cookie rules with comments explaining why each one is a false positive here |
| Trivy SCA | 8 CVEs | `tar` package has known vulnerabilities. It's a transitive dependency of `sqlite3 → node-gyp → tar`. Build-time only — never runs in production. | Created `.trivyignore` with all 8 CVE IDs and a justification for each. Also ran `npm audit fix --force` which updated `sqlite3` from 5.x to 6.x |
| Trivy Image | Same 8 CVEs | Same tar vulnerabilities appear in the container image scan | `.trivyignore` covers both filesystem and image scans automatically |
| OWASP ZAP | 5 WARN alerts | CSP permutations, Permissions-Policy, Cross-Origin-Embedder, Non-Storable Content, Auth Request identified. These are informational for a simple lab app with two routes. | Set `continue-on-error: true`. In production you'd tune the rules file or fix the headers — for a learning lab, strict DAST enforcement adds noise without value |

The key lesson from debugging: every exclusion needs a paper trail. If you suppress a finding without explaining why, the next person will either ignore all findings (bad) or spend hours investigating a false positive (wasteful). Every exclusion in this repo has a comment.

---

## How to run this yourself

### The app

```bash
git clone https://github.com/SanaullahAmanullah/taskboard-sdlc-lab.git
cd taskboard-sdlc-lab
npm install
export SESSION_SECRET="pick-something-random-here"
node app.js
```

Open `http://localhost:3000`. Login with `admin` / `admin123` or `user` / `user123`.

Try logging in with `admin'--` as the username and any password. It won't work anymore — that's Step 3.

Try accessing `/admin` as the `user` account. You'll get a 403 — that's Step 4.

### The Docker container

```bash
docker build -t taskboard .
docker run -p 3000:3000 -e SESSION_SECRET="docker-secret" taskboard
```

### Running individual security checks

```bash
# Secrets
gitleaks detect --source .

# SAST
semgrep --config p/javascript .

# Dependency scan
trivy fs --severity HIGH,CRITICAL .

# Container scan
docker build -t taskboard . && trivy image --severity HIGH,CRITICAL taskboard

# Config scan
trivy config .

# DAST (needs the app running first)
export SESSION_SECRET="zap-test-secret"
node app.js &
docker run -v $(pwd):/zap/wrk:ro -t zaproxy/zap-stable zap-baseline.py -t http://host.docker.internal:3000
```

### Forking and running the pipeline

The GitHub Actions workflows are in `.github/workflows/`. If you fork this repo, they'll run automatically on your first push. No configuration needed — all scanners use public Docker images and GitHub's built-in tokens.

---

## What the pipeline looks like when it works

```
✅ Secret Scanning      12s   Gitleaks — no secrets found
✅ SAST                 23s   Semgrep — 0 findings
✅ SCA                  14s   Trivy — 0 HIGH/CRITICAL dependencies
✅ Container Scan       38s   Trivy — image clean
✅ Config Scan          17s   Trivy — Dockerfile and K8s compliant
✅ DAST                 82s   ZAP — 0 FAIL alerts
```

Six green checkmarks. That's what a secure pipeline looks like.

---

## What I'd do differently next time

- **Add rate limiting before Step 5.** It's in the threat model as a Denial of Service risk but I never implemented it. express-rate-limit would take 10 minutes.
- **Use a real session store.** The current app uses in-memory sessions. In production you'd use Redis.
- **Add CSRF tokens.** The logout is a POST but there's no CSRF protection beyond sameSite cookies.
- **Write integration tests for the security controls.** Right now I verify manually with curl. A proper setup would have tests that assert: SQLi returns 401, user gets 403 on /admin, session cookie has HttpOnly.
- **Pin GitHub Action versions to commit SHAs instead of tags.** `uses: actions/checkout@v4` should be `uses: actions/checkout@<full-commit-sha>`. Prevents supply chain attacks through action tag mutation.

These are noted in the threat model but not implemented. They're good next steps for anyone learning from this repo.

---

## Things I learned that aren't in any tutorial

1. **Pipeline debugging is most of the work.** Writing the six workflow YAML files took 30 minutes. Getting them all green took over an hour. Real pipelines are the same — the config is easy, the tuning is hard.

2. **Rule names matter.** ZAP, Semgrep, and Trivy all use slightly different formats for their rule IDs. An exclusion that works locally might not work in CI because the scanner version is different. Always read the CI logs, don't trust that a local test means it works.

3. **`continue-on-error` has a purpose.** Not every scanner needs to block the pipeline. ZAP provides visibility. The other five scanners provide enforcement. Knowing which is which is a judgment call.

4. **Threat modeling before coding changes how you code.** When I wrote the vulnerable app, I was thinking "what features does this need?" When I wrote the fixes, I was thinking "what could go wrong with this component?" Completely different mindset.

5. **The commit history IS the documentation.** Each commit message explains what was fixed, why, and how to verify it. If someone reads the commits in order, they can follow the entire security journey without looking at the code.

---

## Project structure

```
taskboard-sdlc-lab/
├── app.js                          # The application (vulnerable → secure over 6 commits)
├── Dockerfile                      # Multi-stage, non-root, minimal image
├── threat-model/
│   └── THREAT-MODEL.md             # STRIDE analysis — 7 threats, scored and prioritized
├── .github/workflows/
│   ├── secret-scan.yml             # Gitleaks — hardcoded secrets
│   ├── sast.yml                    # Semgrep — static analysis
│   ├── sca.yml                     # Trivy — dependency scanning
│   ├── container-scan.yml          # Trivy — container image scanning
│   ├── config-scan.yml             # Trivy — Docker/K8s misconfig scanning
│   └── dast.yml                    # OWASP ZAP — runtime scanning
├── k8s/
│   └── deployment.yaml             # Kubernetes deployment with pod security
├── .zap/
│   └── rules.tsv                   # ZAP alert threshold configuration
├── .trivyignore                    # Accepted vulnerabilities with justifications
└── README.md
```
