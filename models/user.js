import { pool } from '../db/index.js';
import argon2 from 'argon2';
import { nanoid } from 'nanoid';

export async function createUser(email, rawPassword) {
    const userId = nanoid();
    const normalizedEmail = email.toLowerCase().trim();
    // Allow tuning Argon2 cost in env for faster local/dev workflows.
    const argonOptions = { type: argon2.argon2id };
    if (process.env.ARGON2_TIME_COST) argonOptions.timeCost = parseInt(process.env.ARGON2_TIME_COST, 10);
    const passwordHash = await argon2.hash(rawPassword, argonOptions);
    
    try {
        await pool.query(
            `INSERT INTO Users (id, email, passwordHash) VALUES ($1, $2, $3)`,
            [userId, normalizedEmail, passwordHash]
        );
        return userId;
    } catch (err) {
        if (err.code === '23505') {
            throw new Error('Email already exists');
        }
        throw err;
    }
}

export async function findUserByEmail(email) {
    const normalizedEmail = email.toLowerCase().trim();
    const result = await pool.query(
        `SELECT id, email, passwordHash, mfaSecret FROM Users WHERE email = $1`,
        [normalizedEmail]
    );
    return result.rows[0];
}

export async function findUserById(id) {
    const result = await pool.query(
        `SELECT * FROM Users WHERE id = $1`,
        [id]
    );
    return result.rows[0];
}

export async function verifyPassword(user, rawPassword) {
    if (!user) return false;
    // Handle both camelCase and lowercase due to PostgreSQL column name handling
    const hash = user.passwordHash || user.passwordhash;
    if (!hash) {
        console.error('[verifyPassword] No password hash found for user:', user.id);
        return false;
    }
    return await argon2.verify(hash, rawPassword);
}

export async function setMfaSecret(userId, secret) {
    await pool.query(
        `UPDATE Users SET mfaSecret = $1 WHERE id = $2`,
        [secret, userId]
    );
}

