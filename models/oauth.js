import { pool } from '../db/index.js';
import crypto from 'crypto';

export async function saveAuthCode(code, clientId, userId, redirectUri, scopes, codeChallenge, codeChallengeMethod, ttlMinutes = 10) {
    const expiresAt = Date.now() + ttlMinutes * 60 * 1000;
    await pool.query(
        `INSERT INTO AuthCodes (code, clientid, userid, redirecturi, scopes, codechallenge, codechallengemethod, expiresat)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [code, clientId, userId, redirectUri, JSON.stringify(scopes), codeChallenge, codeChallengeMethod, expiresAt]
    );
}

export async function getAuthCode(code) {
    const result = await pool.query(
        `SELECT * FROM AuthCodes WHERE code = $1`,
        [code]
    );
    let authCode = result.rows[0];
    if (authCode) {
        // Normalize lowercase columns to camelCase
        authCode.clientId = authCode.clientid;
        authCode.userId = authCode.userid;
        authCode.redirectUri = authCode.redirecturi;
        authCode.codeChallenge = authCode.codechallenge;
        authCode.codeChallengeMethod = authCode.codechallengemethod;
        authCode.expiresAt = authCode.expiresat;
        
        authCode.scopes = JSON.parse(authCode.scopes);
        if (Date.now() > authCode.expiresAt) {
            await deleteAuthCode(code);
            return null;
        }
    }
    return authCode;
}

export async function deleteAuthCode(code) {
    await pool.query(`DELETE FROM AuthCodes WHERE code = $1`, [code]);
}

export async function saveTokens(accessToken, refreshToken, clientId, userId, ttlHours = 24) {
    const id = crypto.randomUUID();
    const expiresAt = Date.now() + ttlHours * 60 * 60 * 1000;
    await pool.query(
        `INSERT INTO Tokens (id, accesstoken, refreshtoken, clientid, userid, expiresat)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [id, accessToken, refreshToken, clientId, userId, expiresAt]
    );
}

export async function revokeRefreshToken(refreshToken) {
    const result = await pool.query(
        `UPDATE Tokens SET revoked = 1 WHERE refreshtoken = $1`,
        [refreshToken]
    );
    return result.rowCount > 0;
}

export async function isTokenValid(refreshToken) {
    const result = await pool.query(
        `SELECT * FROM Tokens WHERE refreshtoken = $1 AND revoked = 0`,
        [refreshToken]
    );
    let token = result.rows[0];
    if (!token) return false;
    // Normalize lowercase columns
    token.expiresAt = token.expiresat;
    if (Date.now() > token.expiresAt) return false;
    return true;
}

export async function getTokensByUserId(userId) {
    const result = await pool.query(
        `SELECT * FROM Tokens WHERE userid = $1 AND revoked = 0`,
        [userId]
    );
    return result.rows.map(token => {
        // Normalize lowercase columns
        return {
            ...token,
            accesstoken: token.accesstoken || token.accessToken,
            refreshtoken: token.refreshtoken || token.refreshToken,
            clientid: token.clientid || token.clientId,
            userid: token.userid || token.userId,
            expiresat: token.expiresat || token.expiresAt,
        };
    });
}

