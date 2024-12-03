const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const { generate2FACode, hashCode, verifyCode } = require('../utils/twoFAUtils');
const { send2FACodeByEmail } = require('../services/emailService');
const cryptoUtils = require('../utils/cryptoUtils');

const JWT_SECRET = process.env.JWT_SECRET;

exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const hashedPassword = await cryptoUtils.hashPassword(password);

        const user = await User.create({ username, email, password: hashedPassword });
        res.status(201).json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
};

exports.login = async (req, res) => {
    const { email, password, token } = req.body;

    try {
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        const isPasswordValid = await cryptoUtils.verifyPassword(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        if (user.twofa_enabled) {
            if (!token) {
                return res.status(400).json({ error: '2FA code is required' });
            }

            const isCodeValid = await verifyCode(token, user.twofa_code); 
            if (!isCodeValid) {
                return res.status(400).json({ error: 'Invalid 2FA token' });
            }
        }

        const jwtToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30s' });
        res.status(200).json({ message: 'Login successful', token: jwtToken });

        user.twofa_code = null;
        user.twofa_code_expiry = null;
        await user.save();

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

exports.enable2FA = async (req, res) => {
    try {
        const user = await User.findByPk(req.user.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        exports.generate2FACode = () => {
            const code = Math.floor(100000 + Math.random() * 900000); // Gera um código de 6 dígitos
            return code.toString();
        };

        user.twofa_code = await hashCode(code); // Armazena o código criptografado no banco
        user.twofa_code_expiry = Date.now() + 300000; // 5 minutos
        user.twofa_enabled = true;
        await user.save();

        res.status(200).json({ message: '2FA enabled, check your email for the verification code' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
};
