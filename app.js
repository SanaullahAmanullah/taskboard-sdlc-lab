// ============================================================
// TASKBOARD — Step 3: Fix SQL Injection + Plaintext Passwords
// ============================================================
// Fixed:
//   ✅ Parameterized queries — SQL injection blocked
//   ✅ bcrypt password hashing — plaintext passwords gone
//   ✅ SESSION_SECRET from env — no hardcoded secret
//
// Still vulnerable (will fix in later steps):
//   ❌ No RBAC — any logged-in user can still access /admin
//   ❌ No session regeneration after login
//   ❌ Session cookie missing HttpOnly, secure, sameSite
//   ❌ No security headers (X-Powered-By still exposed)
// ============================================================

const sqlite3 = require("sqlite3").verbose();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 12;

// ✅ FIXED: Secret from environment, not hardcoded
if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET environment variable is required");
    process.exit(1);
}

// ── Database Setup ──────────────────────────────────────────
const db = new sqlite3.Database("./taskboard.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,    -- ✅ Now stores bcrypt hash, not plaintext
            role TEXT
        )
    `);

    // ✅ FIXED: Passwords hashed with bcrypt before storage
    createDefaultUsers();
});

async function createDefaultUsers() {
    try {
        const adminHash = await bcrypt.hash("admin123", SALT_ROUNDS);
        const userHash = await bcrypt.hash("user123", SALT_ROUNDS);

        db.run(
            `INSERT OR IGNORE INTO users (id, username, password, role) VALUES (?, ?, ?, ?)`,
            [1, "admin", adminHash, "admin"]
        );
        db.run(
            `INSERT OR IGNORE INTO users (id, username, password, role) VALUES (?, ?, ?, ?)`,
            [2, "user", userHash, "user"]
        );
    } catch (err) {
        console.error("Failed to create default users:", err.message);
    }
}

// ── Middleware ──────────────────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ⚠️ STILL VULNERABLE: Cookie flags not set yet
app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: true,  // ⚠️ Will fix in Step 5
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

// ✅ FIXED: Parameterized query + bcrypt comparison
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    // ✅ Parameterized query — SQL injection impossible
    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err) {
                return res.status(500).send("Database error");
            }

            if (!user) {
                return res.status(401).send("Invalid credentials");
            }

            // ✅ bcrypt comparison — compares hash, not plaintext
            const valid = await bcrypt.compare(password, user.password);

            if (!valid) {
                return res.status(401).send("Invalid credentials");
            }

            // ⚠️ STILL VULNERABLE: No session regeneration
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
        }
    );
});

// ⚠️ STILL VULNERABLE: No RBAC — any logged-in user can access /admin
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
