# TaskBoard — STRIDE Threat Model

## What is STRIDE?

STRIDE is a framework for finding threats. Instead of asking "is this secure?", you ask six specific questions — one per category. If the answer is "yes, this could happen," you have a threat. If the answer is "no, we prevented it," you have a security control.

| Category | The Question | Real-World Analogy |
|---|---|---|
| **S**poofing | Can someone pretend to be someone else? | Fake ID at a bar |
| **T**ampering | Can someone modify data they shouldn't? | Changing the amount on a check |
| **R**epudiation | Can someone deny doing something? | "I never signed that contract" |
| **I**nformation Disclosure | Can someone see data they shouldn't? | Medical records left on a desk |
| **D**enial of Service | Can someone make the service unavailable? | Blocking the entrance to a store |
| **E**levation of Privilege | Can someone do things they're not allowed to? | Regular employee accessing CEO's office |

**The key insight:** You don't need to memorize STRIDE. You need to learn to ask these six questions about every component in your system. The framework just makes sure you don't forget one.

---

## 1. System Overview

TaskBoard is a Node.js/Express web app with a SQLite database. It runs in a Docker container. CI/CD runs on GitHub Actions.

```
┌──────────┐     HTTP      ┌──────────────┐     SQL      ┌──────────┐
│  Browser  │ ──────────→  │   Express     │ ──────────→ │  SQLite  │
│  (User)   │ ←──────────  │   (app.js)    │ ←────────── │   (DB)   │
└──────────┘               └──────────────┘             └──────────┘
                                  │
                                  │ Git push
                                  ▼
                           ┌──────────────┐
                           │  GitHub       │
                           │  Actions      │
                           └──────────────┘
```

### Trust Boundaries

A trust boundary is any point where data crosses from a "trusted" zone to an "untrusted" zone — or vice versa. Every boundary is a place where threats live.

| ID | Boundary | Why It's a Boundary |
|---|---|---|
| **TB-01** | Browser → Express | User controls everything in the HTTP request. Headers, body, method — all attacker-controlled. |
| **TB-02** | Express → SQLite | The app sends queries to the database. If user input reaches the query without sanitization, the attacker controls the database. |
| **TB-03** | Git Push → GitHub Actions | Code committed to the repo gets executed by CI/CD. Malicious code, leaked secrets, or workflow tampering can compromise the pipeline. |

---

## 2. STRIDE Threat Analysis

Each threat is numbered. TH-01, TH-02, etc. The format: **What** could happen, **where** it happens in the code, **why** it's a threat, and **how** to fix it.

---

### TH-01: SQL Injection — Authentication Bypass

**STRIDE Category: Tampering** — the attacker modifies the SQL query by injecting SQL syntax into the username field.

**Why this is Tampering and not Spoofing:** The attacker isn't pretending to be admin by stealing credentials. They're modifying the SQL query itself — tampering with the database operation — to make the database say "this is admin" when it shouldn't.

**Affected Component:** Login endpoint (`POST /login`)
**Trust Boundary:** TB-02 (Express → SQLite)
**Code Location:** `app.js:79` — string concatenation in SQL query

```javascript
// ⚠️ VULNERABLE: User input concatenated into SQL string
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Attack:** `username=admin'--&password=anything` produces:
```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = 'anything'
```
The `--` comments out the password check. The attacker logs in as admin without knowing the password.

**Verified:** ✅ Confirmed in testing — `admin'--` with password `anything` returns 200 with admin session.

**Fix:** Parameterized queries. Never concatenate user input into SQL.

```javascript
// ✅ SECURE: Parameterized query
db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], ...)
```

---

### TH-02: Plaintext Password Storage

**STRIDE Category: Information Disclosure** — if anyone obtains the database file, they can read every user's password. No cracking needed. Just open the file.

**Why this is Information Disclosure and not Tampering:** The attacker isn't modifying data. They're reading something they shouldn't be able to read — the plaintext passwords.

**Affected Component:** SQLite Database
**Trust Boundary:** TB-02 (Express → SQLite)
**Code Location:** `app.js:26-33` — INSERT with plaintext password

```javascript
// ⚠️ VULNERABLE: Password stored as-is
db.run(`INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (1, 'admin', 'admin123', 'admin')`);
```

**Verified:** ✅ Confirmed in testing — `sqlite3 taskboard.db "SELECT * FROM users"` shows plaintext passwords.

**Fix:** bcrypt hashing. Store the hash, never the password itself. Compare hashes on login.

```javascript
// ✅ SECURE: bcrypt with salt rounds
const hash = await bcrypt.hash(password, 12);
db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
       [username, hash, role]);
```

---

### TH-03: Missing Authorization — User Accesses Admin

**STRIDE Category: Elevation of Privilege** — a regular user performs an action that should require admin privileges.

**Why this is Elevation of Privilege:** The regular user (role: "user") accesses `/admin` (role needed: "admin"). They're doing something above their privilege level.

**Affected Component:** Admin route (`GET /admin`)
**Trust Boundary:** TB-01 (Browser → Express)
**Code Location:** `app.js:95-107` — checks for session but NOT for role

```javascript
// ⚠️ VULNERABLE: Only checks if logged in, not if user is admin
app.get("/admin", (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Authentication required");
    }
    // ANY logged-in user reaches this point
    res.send(`<h1>Admin Dashboard</h1>...`);
});
```

**Verified:** ✅ Confirmed in testing — user `user` (role: user) can access `/admin`.

**Fix:** Role-Based Access Control (RBAC). Add middleware that checks `req.session.user.role` before allowing access.

```javascript
// ✅ SECURE: Separate auth check from role check
function requireAdmin(req, res, next) {
    if (req.session.user?.role !== "admin") {
        return res.status(403).send("Forbidden");
    }
    next();
}

app.get("/admin", requireAuth, requireAdmin, (req, res) => { ... });
```

---

### TH-04: Session Fixation — Attacker Hijacks Session

**STRIDE Category: Spoofing** — after login, the session ID stays the same. An attacker who knows the pre-login session ID can use it after the victim logs in.

**Why this is Spoofing:** The attacker uses a known session ID to impersonate the victim after authentication. They're spoofing the victim's identity.

**Affected Component:** Session management
**Trust Boundary:** TB-01 (Browser → Express)
**Code Location:** `app.js:84-88` — session not regenerated after login

```javascript
// ⚠️ VULNERABLE: Same session ID before and after login
req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
};
```

**Attack scenario:**
1. Attacker visits TaskBoard, gets session ID `abc123`
2. Attacker tricks victim into logging in using session ID `abc123` (cookie injection)
3. Attacker uses session ID `abc123` — now it's authenticated as the victim

**Fix:** Regenerate the session ID after successful authentication. Old session ID becomes invalid.

```javascript
// ✅ SECURE: New session ID after login
req.session.regenerate((err) => {
    req.session.user = { id: user.id, username: user.username, role: user.role };
});
```

---

### TH-05: Session Cookie Theft — No HttpOnly Flag

**STRIDE Category: Information Disclosure → Spoofing chain** — JavaScript can read the session cookie. If XSS exists, the attacker's script steals the cookie and sends it to their server. They then impersonate the user.

**Affected Component:** Session cookie configuration
**Trust Boundary:** TB-01 (Browser → Express)
**Code Location:** `app.js:48-53` — express-session config

```javascript
// ⚠️ VULNERABLE: Cookie missing HttpOnly, secure, sameSite
app.use(session({
    secret: "hardcoded-insecure-secret",
    resave: false,
    saveUninitialized: true,   // ⚠️ Creates sessions for unauthenticated users
}));
```

**Fix:** Set `httpOnly: true` (JavaScript can't read it), `secure: true` (HTTPS only), `sameSite: 'lax'` (CSRF protection).

```javascript
// ✅ SECURE
app.use(session({
    cookie: {
        httpOnly: true,    // JavaScript cannot access
        secure: true,      // Only sent over HTTPS
        sameSite: "lax",   // Blocks cross-site requests
        maxAge: 1800000,   // 30 minutes
    }
}));
```

---

### TH-06: Hardcoded Secrets in Source Code

**STRIDE Category: Information Disclosure** — the session secret is in `app.js`. Anyone with repo access (or who finds the code) can forge valid session cookies.

**Affected Component:** Configuration
**Trust Boundary:** TB-03 (Git → CI/CD)
**Code Location:** `app.js:50` — hardcoded secret

```javascript
// ⚠️ VULNERABLE: Secret committed to git history forever
secret: "hardcoded-insecure-secret",
```

**Verified:** ✅ Visible in the source. Also would be caught by Gitleaks in CI/CD.

**Fix:** Environment variables. Secret never touches the codebase.

```javascript
// ✅ SECURE: From environment, crash if missing
if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET environment variable is required");
    process.exit(1);
}
app.use(session({ secret: process.env.SESSION_SECRET, ... }));
```

---

### TH-07: Missing Security Headers

**STRIDE Category: Information Disclosure + Tampering** — the app leaks information about its tech stack and doesn't restrict what the browser can do with the content.

**Affected Component:** HTTP response headers
**Trust Boundary:** TB-01 (Browser → Express)
**Code Location:** Entire app — no security headers set

**What's missing:**
- `X-Powered-By: Express` — tells attackers the tech stack
- No CSP — allows inline scripts, potential XSS vector
- No HSTS — allows downgrade to HTTP
- No X-Frame-Options — allows clickjacking

**Fix:** Helmet middleware. One line, multiple headers.

```javascript
// ✅ SECURE
const helmet = require("helmet");
app.use(helmet());
```

---

## 3. Risk Prioritization

**How we score:** Likelihood (1-3) × Impact (1-3) = Risk Score (1-9)

| Threat | Category | Likelihood | Impact | Score | Priority |
|---|---|---|---|---|---|
| TH-01 | SQL Injection | 3 | 3 | **9** | 🔴 Critical |
| TH-02 | Plaintext Passwords | 3 | 3 | **9** | 🔴 Critical |
| TH-05 | Session Cookie Theft | 2 | 3 | **6** | 🟠 High |
| TH-03 | Missing Authorization | 2 | 3 | **6** | 🟠 High |
| TH-06 | Hardcoded Secrets | 2 | 3 | **6** | 🟠 High |
| TH-04 | Session Fixation | 1 | 3 | **3** | 🟡 Medium |
| TH-07 | Missing Headers | 2 | 2 | **4** | 🟡 Medium |

**Why this order:** You fix what kills you first. SQL injection and plaintext passwords both score 9 — they're trivially exploitable and the impact is total compromise. Session fixation scores 3 because it requires a second vulnerability (cookie injection) to exploit. Fix the 9s first.

---

## 4. Remediation Order

1. **TH-01 — SQL Injection** → Parameterized queries (Step 3)
2. **TH-02 — Plaintext Passwords** → bcrypt hashing (Step 3)
3. **TH-03 — Missing RBAC** → requireAdmin middleware (Step 4)
4. **TH-04 — Session Fixation** → Session regeneration (Step 5)
5. **TH-05 — Cookie Theft** → HttpOnly, secure, sameSite (Step 5)
6. **TH-06 — Hardcoded Secrets** → Environment variables (Step 6)
7. **TH-07 — Missing Headers** → Helmet (Step 6)

---

*Threat model written by building the vulnerable app first, then asking the six STRIDE questions about each component. Every threat maps to a specific line of code in `app.js`.*
