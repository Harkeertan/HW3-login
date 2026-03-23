const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new sqlite3.Database('./database.sqlite');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT
    )`);

    //testcase for database
    const testEmail = 'test@example.com';
    const testPassword = 'password123';
    bcrypt.hash(testPassword, 10, (err, hash) => {
        if (err) throw err;
        db.run(`INSERT OR IGNORE INTO users (email, password) VALUES (?, ?)`, [testEmail, hash]);
    });
});

//endpoint for login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    if (!email.includes('@')) {
        return res.status(400).json({ error: 'Invalid email format' });
    }
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    db.get(`SELECT password FROM users WHERE email = ?`, [email], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!row) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        bcrypt.compare(password, row.password, (err, result) => {
            if (err) {
                return res.status(500).json({ error: 'Internal error' });
            }
            if (!result) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }
            res.json({ message: 'Login successful' });
        });
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});