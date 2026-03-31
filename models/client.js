import { pool } from '../db/index.js';
import crypto from 'crypto';
import { nanoid } from 'nanoid';

export async function createClient(name, redirectUris, allowedGrants = 'authorization_code,refresh_token') {
    const clientId = nanoid(24);
    const clientSecret = crypto.randomBytes(32).toString('hex');
    const secretHash = crypto.createHash('sha256').update(clientSecret).digest('hex');
    
    await pool.query(
        `INSERT INTO Clients (clientId, secretHash, redirectUris, allowedGrants, name) VALUES ($1, $2, $3, $4, $5)`,
        [clientId, secretHash, JSON.stringify(redirectUris), allowedGrants, name]
    );
    
    return { clientId, clientSecret };
}

export async function findClientById(clientId) {
    const result = await pool.query(
        `SELECT * FROM Clients WHERE clientid = $1`,
        [clientId]
    );
    const client = result.rows[0];
    if (client) {
        // PostgreSQL returns lowercase columns; normalize to camelCase
        client.clientId = client.clientid;
        client.secretHash = client.secrethash;
        client.redirectUris = client.redirecturis;
        client.allowedGrants = client.allowedgrants;
        
        // Parse redirectUris JSON array
        try {
            if (typeof client.redirectUris === 'string' && client.redirectUris.length) {
                client.redirectUris = JSON.parse(client.redirectUris);
            } else if (Array.isArray(client.redirectUris)) {
                // already an array
            } else {
                client.redirectUris = [];
            }
        } catch (err) {
            console.warn('Warning: failed to parse redirectUris for client', clientId, err.message);
            client.redirectUris = [];
        }
    }
    return client;
}

export async function verifyClientSecret(clientId, plainSecret) {
    const client = await findClientById(clientId);
    if (!client) return false;

    const computedHash = crypto.createHash('sha256').update(plainSecret).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(client.secretHash), Buffer.from(computedHash));
}

