import { createUser, findUserByEmail, verifyPassword, findUserById, setMfaSecret } from '../models/user.js';
import { authenticator } from '@otplib/preset-default';
import qrcode from 'qrcode';
import { signToken } from '../utils/crypto.js';

export async function register(req, res) {
    try {
        const { email, password } = req.body;
        console.log('📝 Registration attempt:', { email, passwordLength: password?.length });
        
        if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
        
        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            console.log('❌ Invalid email format:', email);
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        // Validate password strength
        if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
        if (!/[A-Z]/.test(password)) return res.status(400).json({ error: 'Password must contain uppercase letter' });
        if (!/[0-9]/.test(password)) return res.status(400).json({ error: 'Password must contain number' });
        if (!/[!@#$%^&*]/.test(password)) return res.status(400).json({ error: 'Password must contain special character (!@#$%^&*)' });
        
        const existing = await findUserByEmail(email);
        if (existing) return res.status(400).json({ error: 'User already exists' });
        
        const userId = await createUser(email, password);
        console.log('✅ User registered successfully:', userId);
        res.status(201).json({ message: 'User created successfully', userId });
    } catch (err) {
        console.error('❌ Registration error:', err.message, err);
        res.status(500).json({ error: 'Server error during registration' });
    }
}

export async function login(req, res) {
    try {
        const { email, password } = req.body;
        // Minimal logging to avoid slowing down auth path
        const user = await findUserByEmail(email);
        
        if (!user) {
            console.log('❌ User not found:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const passwordValid = await verifyPassword(user, password);
        if (!passwordValid) return res.status(401).json({ error: 'Invalid credentials' });
        
        // Return a temporary token to pass MFA if MFA is set up
        if (user.mfasecret) {
            const tempToken = signToken({ sub: user.id, temp: true }, '5m');
            return res.status(200).json({ requireMfa: true, tempToken });
        }

        // Issue a session token (or JWT) to the user for our UI
        const sessionToken = signToken({ sub: user.id }, '24h');
        res.status(200).json({ message: 'Login successful', sessionToken });
    } catch (err) {
        console.error('❌ Login error:', err.message);
        res.status(500).json({ error: 'Server error during login' });
    }
}

export async function setupMfa(req, res) {
    try {
        // Assume req.user is set by auth middleware validating the session
        const user = await findUserById(req.user.sub);
        if (!user) return res.status(404).json({ error: 'User not found' });
        
        const secret = authenticator.generateSecret();
        const otpauthUrl = authenticator.keyuri(user.email, 'AuthPoint', secret);
        
        const qrCodeUrl = await qrcode.toDataURL(otpauthUrl);
        await setMfaSecret(user.id, secret);
        
        res.json({ secret, qrCodeUrl });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error setting up MFA' });
    }
}

export async function verifyMfa(req, res) {
    try {
        const { code } = req.body;
        // req.user is decoded from tempToken by requireTempToken middleware
        const user = await findUserById(req.user.sub);
        if (!user || !user.mfasecret) return res.status(400).json({ error: 'Invalid user or MFA not setup' });
        
        const isValid = authenticator.verify({ token: code, secret: user.mfasecret });
        if (!isValid) return res.status(401).json({ error: 'Invalid MFA code' });
        
        const sessionToken = signToken({ sub: user.id }, '24h');
        res.json({ message: 'MFA verified', sessionToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error verifying MFA' });
    }
}
