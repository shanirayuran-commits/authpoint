import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const KEYS_FILE = path.join(__dirname, '..', 'keys.json');

let privateKey, publicKey;

export function loadOrGenerateKeys() {
    if (fs.existsSync(KEYS_FILE)) {
        const keys = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
        privateKey = keys.privateKey;
        publicKey = keys.publicKey;
        console.log('Loaded existing RS256 key pair.');
    } else {
        const { publicKey: pub, privateKey: priv } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        privateKey = priv;
        publicKey = pub;
        fs.writeFileSync(KEYS_FILE, JSON.stringify({ privateKey, publicKey }, null, 2));
        console.log('Generated new RS256 key pair.');
    }
}

export function signToken(payload, expiresIn = '1h') {
    if (!privateKey) throw new Error('RS256 Keys not initialized');
    return jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn });
}

export function verifyToken(token) {
    if (!publicKey) throw new Error('RS256 Keys not initialized');
    return jwt.verify(token, publicKey, { algorithms: ['RS256'] });
}

export function getPublicKey() {
    return publicKey;
}

// Generate an opaque string for refresh tokens
export function generateOpaqueToken() {
    return crypto.randomBytes(40).toString('hex');
}

// SHA256 hashing for PKCE
export function generateCodeChallenge(verifier) {
    return crypto.createHash('sha256').update(verifier).digest('base64url');
}
