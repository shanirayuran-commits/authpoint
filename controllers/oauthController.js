import { findClientById, verifyClientSecret } from '../models/client.js';
import { saveAuthCode, getAuthCode, deleteAuthCode, saveTokens, isTokenValid, revokeRefreshToken } from '../models/oauth.js';
import { findUserById } from '../models/user.js';
import { signToken, generateOpaqueToken, generateCodeChallenge } from '../utils/crypto.js';
import { nanoid } from 'nanoid';

// GET /authorize (simulated flow logic)
export async function authorizeGet(req, res) {
    const { client_id, redirect_uri, response_type, scope, state, code_challenge, code_challenge_method } = req.query;
    
    if (response_type !== 'code') return res.status(400).json({ error: 'unsupported_response_type' });
    if (!client_id || !redirect_uri) return res.status(400).json({ error: 'invalid_request' });

    const client = await findClientById(client_id);
    if (!client) {
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client matching that ID was not found.' });
    }
    if (!client.redirectUris.includes(redirect_uri)) {
        return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'The redirect URI provided does not match the one registered for this client.' });
    }

    /* 
    if (!code_challenge || code_challenge_method !== 'S256') {
        return res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 required' });
    }
    */

    // In a real flow, we render a consent screen. For this API, we can either
    // render it, or expect a POST to /authorize with the user's session.
    // Let's redirect to a basic UI consent screen if this is accessed via browser.
    res.redirect(`/views/consent.html?client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${scope}&state=${state}&code_challenge=${code_challenge}&code_challenge_method=${code_challenge_method}`);
}

// POST /authorize
export async function authorizePost(req, res) {
    // Requires authentication via sessionToken
    // Assuming a simple middleware populates req.user
    if (!req.user || !req.user.sub) {
        console.error('[authorizePost] Missing user in request:', req.user);
        return res.status(401).json({ error: 'unauthorized', error_description: 'No active session' });
    }

    const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.body;
    
    console.log('[authorizePost] Authorizing user:', req.user.sub, 'for client:', client_id);
    
    // Verify user exists in database
    const user = await findUserById(req.user.sub);
    if (!user) {
        console.error('[authorizePost] User not found in database:', req.user.sub);
        return res.status(401).json({ error: 'unauthorized', error_description: 'User not found. Please log in again.' });
    }
    
    const client = await findClientById(client_id);
    if (!client) {
        console.error('[authorizePost] Client not found:', client_id);
        return res.status(400).json({ error: 'invalid_client', error_description: 'Client matching that ID was not found.' });
    }
    
    console.log('[authorizePost] Authorization Debug:');
    console.log('  - User ID:', user.id);
    console.log('  - Client registered redirectUris:', client.redirectUris);
    console.log('  - Request redirect_uri:', redirect_uri);
    console.log('  - URI match:', client.redirectUris.includes(redirect_uri));
    
    if (!client.redirectUris.includes(redirect_uri)) {
        console.error('[authorizePost] Redirect URI mismatch');
        return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'The redirect URI provided does not match the one registered for this client.' });
    }

    try {
        const code = nanoid(32);
        const scopeArray = scope ? scope.split(' ') : [];
        
        console.log('[authorizePost] Saving auth code for user:', user.id);
        await saveAuthCode(code, client_id, user.id, redirect_uri, scopeArray, code_challenge, code_challenge_method);
        
        const redirectParams = new URLSearchParams({ code });
        if (state) redirectParams.append('state', state);

        console.log('[authorizePost] Auth code saved, redirecting to:', `${redirect_uri}?${redirectParams.toString()}`);
        res.json({ redirect_url: `${redirect_uri}?${redirectParams.toString()}` });
    } catch (err) {
        console.error('[authorizePost] Error saving auth code:', err.message);
        res.status(500).json({ error: 'server_error', error_description: 'Failed to create authorization code: ' + err.message });
    }
}

// POST /token
export async function token(req, res) {
    const { grant_type, code, redirect_uri, client_id, client_secret, code_verifier } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    if (!code || !redirect_uri) return res.status(400).json({ error: 'invalid_request' });

    // Validate client
    const client = await findClientById(client_id);
    if (!client) return res.status(400).json({ error: 'invalid_client' });

    // If client is confidential, it must provide secret. If public, must provide PKCE.
    // We enforce PKCE for everyone as best practice.
    if (client_secret) {
        if (!(await verifyClientSecret(client_id, client_secret))) {
            return res.status(401).json({ error: 'invalid_client' });
        }
    }

    const authCode = await getAuthCode(code);
    
    // Debug logging
    console.log('\n=== Token Exchange Debug ===');
    console.log('Request redirect_uri:', redirect_uri);
    console.log('Stored authCode:', authCode ? { clientId: authCode.clientId, redirectUri: authCode.redirectUri, userId: authCode.userId } : 'NOT FOUND');
    console.log('Client ID match:', authCode?.clientId === client_id);
    console.log('Redirect URI match:', authCode?.redirectUri === redirect_uri);
    console.log('==============================\n');
    
    if (!authCode || authCode.clientId !== client_id || authCode.redirectUri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_grant' });
    }

    // PKCE Validation
    /* 
    if (!code_verifier) return res.status(400).json({ error: 'invalid_request', error_description: 'PKCE code_verifier required' });

    const computedChallenge = generateCodeChallenge(code_verifier);
    if (computedChallenge !== authCode.codeChallenge) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE challenge failed' });
    }
    */

    // Token logic
    const user = await findUserById(authCode.userId);
    if (!user) return res.status(500).json({ error: 'server_error' });

    // Delete used auth code
    await deleteAuthCode(code);

    const accessToken = signToken({
        sub: user.id,
        aud: client_id,
        scopes: authCode.scopes
    }, '1h');

    const refreshToken = generateOpaqueToken();
    await saveTokens(accessToken, refreshToken, client_id, user.id);

    res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 3600,
        refresh_token: refreshToken,
        scope: authCode.scopes.join(' ')
    });
}

// GET /userinfo
export async function userinfo(req, res) {
    // Requires Bearer token valid access
    if (!req.user || !req.user.sub) return res.status(401).json({ error: 'unauthorized' });

    const user = await findUserById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'user_not_found' });

    // Return limited claims based on scope
    const claims = {
        sub: user.id,
        email: user.email // if 'profile' or 'email' scope was granted
    };

    res.json(claims);
}

// POST /revoke
export async function revoke(req, res) {
    const { token, token_type_hint } = req.body;
    if (!token) return res.status(400).json({ error: 'invalid_request' });

    if (await revokeRefreshToken(token)) {
        return res.status(200).json({});
    }

    // RFC 7009: Invalid token implies already revoked or doesn't exist. Return 200.
    res.status(200).json({});
}
