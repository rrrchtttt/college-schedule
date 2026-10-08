const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');

const app = express();
const PORT = Number(process.env.PORT || 10000);

const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || '').trim();
const ADMIN_PASSWORD_HASH = String(process.env.ADMIN_PASSWORD_HASH || '').trim();
const SESSION_SECRET = String(process.env.SESSION_SECRET || '').trim();

if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
    throw new Error('Missing required environment variables: ADMIN_EMAIL, ADMIN_PASSWORD_HASH, SESSION_SECRET');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '25mb' }));

const COOKIE_NAME = 'vitya_session';
const SESSION_TTL_SECONDS = 60 * 60 * 12;
const DATA_FILE = path.join(__dirname, 'server-data.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const SCHEDULE_FILE = path.join(__dirname, 'schedule.json');

function readJsonFile(file, fallback) {
    try {
        if (!fs.existsSync(file)) return fallback;
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
        return fallback;
    }
}

function writeJsonFile(file, value) {
    const temp = `${file}.tmp`;
    fs.writeFileSync(temp, JSON.stringify(value, null, 2), 'utf8');
    fs.renameSync(temp, file);
}

function loadStore() {
    const schedule = readJsonFile(SCHEDULE_FILE, {});
    const stored = readJsonFile(DATA_FILE, null);
    if (stored && typeof stored === 'object' && stored.daysData && typeof stored.daysData === 'object') {
        return {
            daysData: stored.daysData,
            timetableData: stored.timetableData && typeof stored.timetableData === 'object' ? stored.timetableData : schedule,
            attendance: stored.attendance && typeof stored.attendance === 'object' ? stored.attendance : {}
        };
    }
    return { daysData: {}, timetableData: schedule, attendance: {} };
}

let store = loadStore();
let users = readJsonFile(USERS_FILE, []);
if (!Array.isArray(users)) users = [];

function saveStore() { writeJsonFile(DATA_FILE, store); }
function saveUsers() { writeJsonFile(USERS_FILE, users); }

function createSessionToken(role, email) {
    const payload = {
        exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
        nonce: crypto.randomBytes(16).toString('hex'),
        role,
        email
    };
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    return `${encoded}.${signature}`;
}

function readSession(token) {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encoded, signature] = parts;
    let expected;
    try {
        expected = crypto.createHmac('sha256', SESSION_SECRET).update(encoded).digest('base64url');
    } catch { return null; }
    const a = Buffer.from(signature);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
        if (!Number.isFinite(payload.exp) || payload.exp <= Math.floor(Date.now() / 1000)) return null;
        if (!['admin', 'user'].includes(payload.role)) return null;
        return { role: payload.role, email: String(payload.email || '') };
    } catch { return null; }
}

function getCookieValue(req, name) {
    const header = req.headers.cookie || '';
    for (const part of header.split(';')) {
        const [key, ...valueParts] = part.trim().split('=');
        if (key === name) return decodeURIComponent(valueParts.join('='));
    }
    return null;
}

function getSession(req) { return readSession(getCookieValue(req, COOKIE_NAME)); }
function requireLogin(req, res, next) {
    const session = getSession(req);
    if (!session) return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED' });
    req.session = session;
    next();
}
function requireAdmin(req, res, next) {
    const session = getSession(req);
    if (!session || session.role !== 'admin') return res.status(403).json({ ok: false, error: 'ADMIN_REQUIRED' });
    req.session = session;
    next();
}

const attempts = new Map();
const MAX_ATTEMPTS = 10;
const WINDOW_MS = 15 * 60 * 1000;
function rateLimitLogin(req, res, next) {
    const ip = req.ip || 'unknown';
    const now = Date.now();
    const current = attempts.get(ip);
    if (!current || current.resetAt <= now) {
        attempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
        return next();
    }
    if (current.count >= MAX_ATTEMPTS) return res.status(429).json({ ok: false, error: 'TOO_MANY_ATTEMPTS' });
    current.count += 1;
    next();
}

function setSessionCookie(res, role, email) {
    const token = createSessionToken(role, email);
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        maxAge: SESSION_TTL_SECONDS * 1000,
        path: '/'
    });
}

app.post('/api/auth/login', rateLimitLogin, async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!email || !password) return res.status(401).json({ ok: false });

    try {
        if (email.toLowerCase() === ADMIN_EMAIL.toLowerCase() && await bcrypt.compare(password, ADMIN_PASSWORD_HASH)) {
            setSessionCookie(res, 'admin', ADMIN_EMAIL);
            return res.json({ ok: true, role: 'admin' });
        }

        const user = users.find(u => String(u.email).toLowerCase() === email.toLowerCase() && u.active !== false);
        if (user && await bcrypt.compare(password, user.passwordHash)) {
            setSessionCookie(res, 'user', user.email);
            return res.json({ ok: true, role: 'user' });
        }

        return res.status(401).json({ ok: false });
    } catch {
        return res.status(500).json({ ok: false });
    }
});

app.get('/api/auth/me', (req, res) => {
    const session = getSession(req);
    if (!session) return res.status(401).json({ ok: false, role: 'guest' });
    res.set('Cache-Control', 'no-store');
    res.json({ ok: true, role: session.role, email: session.email });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME, { httpOnly: true, secure: true, sameSite: 'lax', path: '/' });
    res.json({ ok: true });
});

app.get('/api/data', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ daysData: store.daysData, timetableData: store.timetableData });
});

app.put('/api/data', requireAdmin, (req, res) => {
    const daysData = req.body?.daysData;
    const timetableData = req.body?.timetableData;
    if (!daysData || typeof daysData !== 'object' || Array.isArray(daysData) || !timetableData || typeof timetableData !== 'object' || Array.isArray(timetableData)) {
        return res.status(400).json({ ok: false, error: 'INVALID_DATA' });
    }
    store.daysData = daysData;
    store.timetableData = timetableData;
    saveStore();
    res.json({ ok: true });
});

app.post('/api/data/import', requireAdmin, (req, res) => {
    const daysData = req.body?.daysData;
    const timetableData = req.body?.timetableData;
    if (!daysData || typeof daysData !== 'object' || Array.isArray(daysData) || !timetableData || typeof timetableData !== 'object' || Array.isArray(timetableData)) {
        return res.status(400).json({ ok: false, error: 'INVALID_DATA' });
    }
    store.daysData = daysData;
    store.timetableData = timetableData;
    saveStore();
    res.json({ ok: true });
});

app.get('/api/export', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ version: 3, exportedAt: new Date().toISOString(), daysData: store.daysData, timetableData: store.timetableData, attendance: store.attendance });
});

app.get('/api/users', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ users: users.map(u => ({ email: u.email, name: u.name || '', active: u.active !== false, createdAt: u.createdAt })) });
});

app.post('/api/users', requireAdmin, async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const name = typeof req.body?.name === 'string' ? req.body.name.trim().slice(0, 80) : '';
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 8) return res.status(400).json({ ok: false, error: 'INVALID_USER' });
    if (email === ADMIN_EMAIL.toLowerCase() || users.some(u => u.email.toLowerCase() === email)) return res.status(409).json({ ok: false, error: 'USER_EXISTS' });
    const passwordHash = await bcrypt.hash(password, 12);
    users.push({ email, name, passwordHash, active: true, createdAt: new Date().toISOString() });
    saveUsers();
    res.status(201).json({ ok: true });
});

app.delete('/api/users/:email', requireAdmin, (req, res) => {
    const email = decodeURIComponent(req.params.email).trim().toLowerCase();
    const before = users.length;
    users = users.filter(u => u.email.toLowerCase() !== email);
    if (users.length === before) return res.status(404).json({ ok: false });
    saveUsers();
    res.json({ ok: true });
});

app.post('/api/attendance', requireAdmin, (req, res) => {
    const date = typeof req.body?.date === 'string' ? req.body.date : '';
    const classId = typeof req.body?.classId === 'string' ? req.body.classId : '';
    const status = typeof req.body?.status === 'string' ? req.body.status : '';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !classId || !['present', 'absent', 'late', ''].includes(status)) return res.status(400).json({ ok: false });
    if (!store.attendance[date]) store.attendance[date] = {};
    if (!status) delete store.attendance[date][classId];
    else store.attendance[date][classId] = status;
    saveStore();
    res.json({ ok: true });
});

app.get('/api/attendance', requireAdmin, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ attendance: store.attendance });
});

app.use(express.static(__dirname, { etag: true, maxAge: '1h', index: 'index.html' }));
app.get('/{*splat}', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, '0.0.0.0');
