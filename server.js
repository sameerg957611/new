
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const db = new sqlite3.Database('./database.db');

const JWT_SECRET = 'supersecret';

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Create tables if not exist
db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT)`);
db.run(`CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);

// Seed admin user
const adminUsername = 'sameerg';
const adminPassword = 'hellog';
db.get("SELECT * FROM users WHERE username = ?", [adminUsername], (err, row) => {
    if (!row) {
        const hashed = bcrypt.hashSync(adminPassword, 10);
        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [adminUsername, hashed]);
    }
});

// Auth middleware
function authMiddleware(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'No token provided' });
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Failed to authenticate token' });
        req.userId = decoded.id;
        next();
    });
}

// Routes
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    });
});

app.post('/api/notes', authMiddleware, (req, res) => {
    const { title, content } = req.body;
    db.run("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", [req.userId, title, content], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, title, content });
    });
});

app.get('/api/notes', authMiddleware, (req, res) => {
    db.all("SELECT * FROM notes WHERE user_id = ?", [req.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.delete('/api/notes/:id', authMiddleware, (req, res) => {
    db.run("DELETE FROM notes WHERE id = ? AND user_id = ?", [req.params.id, req.userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
