const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');

const app = express();
const PORT = Number(process.env.PORT || 10000);

const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_EMAIL || !ADMIN_PASSWORD_HASH || !SESSION_SECRET) {
    throw new Error('Missing required environment variables.');
}

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(express.json({ limit: '10kb' }));

const COOKIE_NAME = 'vitya_admin_session';
const SESSION_TTL_SECONDS = 60 * 60 * 12; // 12 hours

function createSessionToken() {
    const payload = {
        exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
        nonce: crypto.randomBytes(16).toString('hex')
    };

    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
        .createHmac('sha256', SESSION_SECRET)
        .update(encoded)
        .digest('base64url');

    return `${encoded}.${signature}`;
}

function isValidSessionToken(token) {
    if (!token || typeof token !== 'string') return false;

    const parts = token.split('.');
    if (parts.length !== 2) return false;

    const [encoded, signature] = parts;

    let expected;
    try {
        expected = crypto
            .createHmac('sha256', SESSION_SECRET)
            .update(encoded)
            .digest('base64url');
    } catch {
        return false;
    }

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return false;
    }

    try {
        const payload = JSON.parse(
            Buffer.from(encoded, 'base64url').toString('utf8')
        );

        return Number.isFinite(payload.exp) &&
            payload.exp > Math.floor(Date.now() / 1000);
    } catch {
        return false;
    }
}

function getCookieValue(req, name) {
    const header = req.headers.cookie || '';

    for (const part of header.split(';')) {
        const [key, ...valueParts] = part.trim().split('=');

        if (key === name) {
            return decodeURIComponent(valueParts.join('='));
        }
    }

    return null;
}

function requireAdmin(req, res, next) {
    const token = getCookieValue(req, COOKIE_NAME);

    if (!isValidSessionToken(token)) {
        return res.status(401).json({ ok: false });
    }

    req.isAdmin = true;
    next();
}

// Простое ограничение частоты попыток входа на экземпляр сервера.
// Оно не выводит логин/пароль и не сохраняет их.
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

    if (current.count >= MAX_ATTEMPTS) {
        return res.status(429).json({ ok: false });
    }

    current.count += 1;
    next();
}

app.post('/api/auth/login', rateLimitLogin, async (req, res) => {
    const email = typeof req.body?.email === 'string'
        ? req.body.email.trim()
        : '';
    const password = typeof req.body?.password === 'string'
        ? req.body.password
        : '';

    // Всегда используем одинаковый ответ при ошибке.
    if (!email || !password) {
        return res.status(401).json({ ok: false });
    }

    try {
        const emailMatches = email.toLowerCase() === ADMIN_EMAIL.toLowerCase();
        const passwordMatches = await bcrypt.compare(
            password,
            ADMIN_PASSWORD_HASH
        );

        if (!emailMatches || !passwordMatches) {
            return res.status(401).json({ ok: false });
        }

        const token = createSessionToken();

        res.cookie(COOKIE_NAME, token, {
            httpOnly: true,
            secure: true,
            sameSite: 'lax',
            maxAge: SESSION_TTL_SECONDS * 1000,
            path: '/'
        });

        return res.json({ ok: true });
    } catch {
        return res.status(500).json({ ok: false });
    }
});

app.get('/api/auth/me', requireAdmin, (req, res) => {
    res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
    res.clearCookie(COOKIE_NAME, {
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/'
    });

    res.json({ ok: true });
});

// Защита от кэширования auth-ответов.
app.use('/api/auth', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
});

// Весь остальной сайт — статический frontend.
app.use(express.static(path.join(__dirname, 'public'), {
    etag: true,
    maxAge: '1h'
}));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0');
