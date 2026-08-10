// ============================================================
// TASKBOARD — Step 4: Fix RBAC + Cookie Security + Security Headers
// ============================================================
// Fixed:
//   ✅ Parameterized queries — SQL injection blocked (Step 3)
//   ✅ bcrypt password hashing (Step 3)
//   ✅ SESSION_SECRET from env (Step 3)
//   ✅ RBAC — requireAdmin middleware blocks regular users (Step 4)
//   ✅ Session regeneration after login (Step 4)
//   ✅ Cookie flags: HttpOnly, secure, sameSite (Step 4)
//   ✅ Security headers via Helmet (Step 4)
// ============================================================

const sqlite3 = require("sqlite3").verbose();
const express = require("express");
const bcrypt = require("bcrypt");
const session = require("express-session");
const helmet = require("helmet");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 12;

if (!process.env.SESSION_SECRET) {
    console.error("SESSION_SECRET environment variable is required");
    process.exit(1);
}

// ── Security Headers ───────────────────────────────────────
app.disable("x-powered-by");

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'"],
                imgSrc: ["'self'", "data:"],
                objectSrc: ["'none'"],
                frameAncestors: ["'none'"],
                upgradeInsecureRequests: [],
            },
        },
        referrerPolicy: { policy: "no-referrer" },
    })
);

// ── Database Setup ──────────────────────────────────────────
const db = new sqlite3.Database("./taskboard.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    `);
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

// ── Session Configuration ───────────────────────────────────
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
    session({
        name: "taskboard.sid",
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            path: "/",
            maxAge: 30 * 60 * 1000, // 30 minutes
        },
    })
);

// ── Auth Middleware ─────────────────────────────────────────

/**
 * requireAuth — blocks unauthenticated users.
 * Call this on any route that requires a logged-in user.
 * Put it BEFORE the route handler in the middleware chain.
 */
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).send("Authentication required");
    }
    next();
}

/**
 * requireAdmin — blocks non-admin users.
 * Call this AFTER requireAuth on admin-only routes.
 * requireAuth runs first, so req.session.user is guaranteed to exist.
 *
 * This is RBAC (Role-Based Access Control):
 * - Authentication answers "who are you?" (requireAuth)
 * - Authorization answers "are you allowed to do this?" (requireAdmin)
 * - They are separate concerns. Never combine them into one check.
 */
function requireAdmin(req, res, next) {
    if (req.session.user.role !== "admin") {
        return res.status(403).send("Forbidden");
    }
    next();
}

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

app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {
            if (err) return res.status(500).send("Database error");
            if (!user) return res.status(401).send("Invalid credentials");

            const valid = await bcrypt.compare(password, user.password);
            if (!valid) return res.status(401).send("Invalid credentials");

            // ✅ FIXED: Regenerate session ID after login
            // This prevents session fixation — old session ID becomes invalid
            req.session.regenerate((err) => {
                if (err) return res.status(500).send("Session error");

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
        }
    );
});

// ✅ FIXED: requireAuth → requireAdmin chain
// requireAuth blocks unauthenticated users (401)
// requireAdmin blocks non-admin users (403)
// Only admins reach the route handler
app.get("/admin", requireAuth, requireAdmin, (req, res) => {
    res.send(`
        <h1>Admin Dashboard</h1>
        <p>Welcome ${req.session.user.username}</p>
        <p>Only administrators can access this page.</p>
        <form action="/logout" method="POST">
            <button>Logout</button>
        </form>
    `);
});

app.post("/logout", requireAuth, (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).send("Logout failed");
        res.clearCookie("taskboard.sid");
        res.redirect("/");
    });
});

app.listen(PORT, () => {
    console.log(`TaskBoard running on http://localhost:${PORT}`);
});
