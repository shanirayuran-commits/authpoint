import { createClient } from '../models/client.js';

export async function registerClient(req, res) {
    try {
        const { name, redirectUris, allowedGrants } = req.body;
        
        if (!name || !redirectUris || !Array.isArray(redirectUris)) {
            return res.status(400).json({ error: 'invalid_request', error_description: 'Name and a list of redirectUris are required.' });
        }

        const client = await createClient(name, redirectUris, allowedGrants);
        res.status(201).json({
            client_id: client.clientId,
            client_secret: client.clientSecret,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            redirect_uris: redirectUris
        });
    } catch (err) {
        console.error('Error registering client:', err);
        res.status(500).json({ error: 'server_error' });
    }
}
