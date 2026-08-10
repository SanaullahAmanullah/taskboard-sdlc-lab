// ============================================================
// TASKBOARD — Step 1: Vulnerable Baseline
// ============================================================
// This version is intentionally vulnerable. Do NOT use in production.
// Each vulnerability will be fixed in subsequent steps:
//
//   ❌ Plaintext passwords in database
//   ❌ SQL injection via string concatenation
//   ❌ No session security (no HttpOnly, no regeneration)
//   ❌ No RBAC — any logged-in user can access /admin
//   ❌ No security headers
//   ❌ x-powered-by header exposed
// ============================================================

const sqlite3 = require("sqlite3").verbose();
const express = require("express");
const session = require("express-session");

const app = express();
const PORT = 3000;

// ── Database Setup ──────────────────────────────────────────
const db = new sqlite3.Database("./taskboard.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            role TEXT
        )
    `);

    // ⚠️ VULNERABILITY: Plaintext passwords
    db.run(`
        INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (1, 'admin', 'admin123', 'admin')
    `);
    db.run(`
        INSERT OR IGNORE INTO users (id, username, password, role)
        VALUES (2, 'user', 'user123', 'user')
    `);
});

// ── Middleware ──────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ⚠️ VULNERABILITY: Session missing HttpOnly, secure, sameSite
app.use(
    session({
        secret: "hardcoded-insecure-secret",
        resave: false,
        saveUninitialized: true,
    })
);

// ── Routes ──────────────────────────────────────────────────

app.get("/", (req, res) => {
    res.send(`
        <h1>TaskBoard</h1>
        <p>Simple task management.</p>
        <h2>Login</h2>
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Username"><br><br>
            <input type="password" name="password" placeholder="Password"><br><br>
            <button type="submit">Login</button>
        </form>
    `);
});

// ⚠️ VULNERABILITY: SQL injection via string concatenation
// ⚠️ VULNERABILITY: Plaintext password comparison
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, user) => {
        if (err) {
            return res.status(500).send("Database error");
        }

        if (!user) {
            return res.status(401).send("Invalid credentials");
        }

        // ⚠️ VULNERABILITY: No session regeneration after login
        req.session.user = {
            id: user.id,
            username: user.username,
            role: user.role,
        };

        res.send(`
            <h2>Welcome ${user.username}</h2>
            <p>Role: ${user.role}</p>
            <a href="/admin">Admin Dashboard</a><br><br>
            <form action="/logout" method="POST">
                <button>Logout</button>
            </form>
        `);
    });
});

// ⚠️ VULNERABILITY: No authorization check — any logged-in user can access
app.get("/admin", (req, res) => {
    if (!req.session.user) {
        return res.status(401).send("Authentication required");
    }

    res.send(`
        <h1>Admin Dashboard</h1>
        <p>Welcome ${req.session.user.username}</p>
        <p>Sensitive admin data would be here.</p>
        <form action="/logout" method="POST">
            <button>Logout</button>
        </form>
    `);
});

app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send("Logout failed");
        res.redirect("/");
    });
});

app.listen(PORT, () => {
    console.log(`TaskBoard running on http://localhost:${PORT}`);
});
