import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

dotenv.config();

if (!process.env.DATABASE_URL) {
    console.error('❌ ERROR: DATABASE_URL environment variable is not set!');
    console.error('Please add DATABASE_URL to your .env file:');
    console.error('DATABASE_URL=postgresql://user:password@host:port/database');
    process.exit(1);
}

// Initialize database pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
    console.error('Unexpected error on idle client', err);
});

// Initialize database tables
export async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS Users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                passwordHash TEXT NOT NULL,
                mfaSecret TEXT
            );

            CREATE TABLE IF NOT EXISTS Clients (
                clientId TEXT PRIMARY KEY,
                secretHash TEXT,
                redirectUris TEXT,
                allowedGrants TEXT,
                name TEXT
            );

            CREATE TABLE IF NOT EXISTS AuthCodes (
                code TEXT PRIMARY KEY,
                clientId TEXT NOT NULL,
                userId TEXT NOT NULL,
                redirectUri TEXT NOT NULL,
                scopes TEXT,
                codeChallenge TEXT,
                codeChallengeMethod TEXT,
                expiresAt BIGINT NOT NULL,
                FOREIGN KEY (clientId) REFERENCES Clients(clientId),
                FOREIGN KEY (userId) REFERENCES Users(id)
            );

            CREATE TABLE IF NOT EXISTS Tokens (
                id TEXT PRIMARY KEY,
                accessToken TEXT NOT NULL,
                refreshToken TEXT UNIQUE NOT NULL,
                clientId TEXT NOT NULL,
                userId TEXT NOT NULL,
                revoked INTEGER DEFAULT 0,
                expiresAt BIGINT NOT NULL,
                FOREIGN KEY (clientId) REFERENCES Clients(clientId),
                FOREIGN KEY (userId) REFERENCES Users(id)
            );
        `);
        console.log('✅ Database initialized successfully.');
    } catch (err) {
        console.error('❌ Error initializing database:', err.message);
        throw err;
    } finally {
        client.release();
    }
}

const db = {
    prepare: (sql) => ({
        run: (...params) => {
            pool.query(sql, params).catch(err => {
                console.error('Query error:', err.message);
                throw err;
            });
        },
        get: async (...params) => {
            const result = await pool.query(sql, params);
            return result.rows[0];
        },
        all: async (...params) => {
            const result = await pool.query(sql, params);
            return result.rows;
        }
    }),
    query: (sql, params) => pool.query(sql, params),
    exec: (sql) => pool.query(sql),
};

export default db;
export { pool };
