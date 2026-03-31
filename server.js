import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { initDB } from './db/index.js';
import { loadOrGenerateKeys, verifyToken } from './utils/crypto.js';
import { register, login, setupMfa, verifyMfa } from './controllers/authController.js';
import { registerClient } from './controllers/clientController.js';
import { authorizeGet, authorizePost, token, userinfo, revoke } from './controllers/oauthController.js';

// Initialization
loadOrGenerateKeys();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

// Serve static views
app.use('/views', express.static(path.join(__dirname, 'public', 'views')));

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10, // Limit each IP to 10 requests per window
    message: 'Too many authentication attempts from this IP, please try again after 15 minutes.'
});

const tokenLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50, // 50 token exchanges
    message: 'Too many requests to the token endpoint.'
});

// Middlewares
function requireBearer(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'unauthorized', error_description: 'Bearer token required' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = verifyToken(token);
        req.user = decoded; // { sub, aud, scopes }
        next();
    } catch (err) {
        return res.status(401).json({ error: 'invalid_token' });
    }
}

// Helper middleware to extract user from tempToken in body
function requireTempToken(req, res, next) {
    const tempToken = req.body.tempToken;
    if (!tempToken) return res.status(401).json({ error: 'unauthorized', error_description: 'tempToken required' });
    try {
        req.user = verifyToken(tempToken);
        next();
    } catch(err) {
        return res.status(401).json({ error: 'unauthorized', error_description: 'Invalid temp token' });
    }
}

// Routes - Auth
app.post('/api/register', authLimiter, register);
app.post('/api/login', authLimiter, login);
app.post('/api/mfa/setup', requireBearer, setupMfa);
app.post('/api/mfa/verify', authLimiter, requireTempToken, verifyMfa);

// Routes - Clients
app.post('/api/clients/register', registerClient);

// Wrapper to handle async errors
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// Routes - OAuth 2.0
// Simple helper middleware to extract user from sessionToken if passed in body/query
function requireSessionToken(req, res, next) {
    const sessionToken = req.body.sessionToken || req.query.sessionToken;
    console.log('[requireSessionToken] Checking for sessionToken...');
    console.log('[requireSessionToken] Token present:', !!sessionToken);
    console.log('[requireSessionToken] Token length:', sessionToken ? sessionToken.length : 0);
    
    if (!sessionToken) {
        console.error('[requireSessionToken] No sessionToken provided');
        return res.status(401).json({ error: 'unauthorized', error_description: 'sessionToken required' });
    }
    try {
        const decoded = verifyToken(sessionToken);
        console.log('[requireSessionToken] Token verified successfully');
        console.log('[requireSessionToken] Decoded token:', { sub: decoded.sub, aud: decoded.aud });
        req.user = decoded;
        next();
    } catch(err) {
        console.error('[requireSessionToken] Token verification failed:', err.message);
        return res.status(401).json({ error: 'unauthorized', error_description: 'Invalid session: ' + err.message });
    }
}

app.get('/authorize', asyncHandler(authorizeGet));
app.post('/authorize', requireSessionToken, asyncHandler(authorizePost));
app.post('/token', tokenLimiter, asyncHandler(token));
app.get('/userinfo', requireBearer, asyncHandler(userinfo));
app.post('/revoke', asyncHandler(revoke));

// OAuth Callback Handler
app.get('/callback', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'views', 'oauth-callback.html'));
});

// Default Route - Redirect to login
app.get('/', (req, res) => {
    res.redirect('/views/login.html');
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('[Global Error Handler]', err);
    res.status(err.status || 500).json({ 
        error: 'server_error', 
        error_description: err.message || 'Internal server error' 
    });
});

// Start Server with async database initialization
const PORT = process.env.PORT || 3000;

async function startServer() {
    try {
        // Initialize database connection pool and create tables
        await initDB();
        
        // Start listening after DB is ready
        app.listen(PORT, () => {
            console.log(`✅ AuthPoint running on http://localhost:${PORT}`);
            console.log(`📘 Visit: http://localhost:${PORT}/views/login.html`);
        });
    } catch (err) {
        console.error('❌ Failed to start server:', err.message || err);
        if (!process.env.DATABASE_URL) {
            console.error('\n⚠️  DATABASE_URL is not set in .env file');
            console.error('Please add: DATABASE_URL=postgresql://user:password@host:port/database');
        }
        process.exit(1);
    }
}

startServer();
