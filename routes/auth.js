const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/user');
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;
const emailService = require('../services/emailService');
const authenticateJWT = require('../middlewares/authMiddleware');
const passport = require('passport');


// Rota de Registro
router.post(
    '/register',
    [
        body('username').notEmpty().withMessage('Username is required'),
        body('email').isEmail().withMessage('Valid email is required'),
        body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;

        try {
            // Verificar se o usuário já existe
            const existingUser = await User.findOne({ where: { email } });
            if (existingUser) {
                return res.status(400).json({ error: 'User already exists' });
            }

            // Criptografar a senha
            const hashedPassword = await bcrypt.hash(password, 10);

            // Criar o usuário
            const user = await User.create({
                username,
                email,
                password: hashedPassword,
            });

            res.status(201).json({ message: 'User registered successfully', userId: user.id });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Rota de Login
router.post(
    '/login',
    [
        body('email').isEmail().withMessage('Valid email is required'),
        body('password').notEmpty().withMessage('Password is required'),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {
            const user = await User.findOne({ where: { email } });
            if (!user) {
                return res.status(400).json({ error: 'Invalid email or password' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(400).json({ error: 'Invalid email or password' });
            }

            // Verificar se 2FA está habilitado
            if (user.twofa_secret) {
                const twofaCode = speakeasy.totp({ secret: user.twofa_secret, encoding: 'base32' });

                // Armazena o código gerado e sua validade no banco
                user.twofa_code = twofaCode;
                user.twofa_code_expiry = new Date(Date.now() + 5 * 60 * 1000); // Código válido por 5 minutos
                await user.save();

                // Envia o código para o e-mail do usuário
                await emailService.send2FACodeByEmail(user.email, twofaCode);

                return res.status(200).json({
                    message: '2FA code sent to email. Verify to continue.',
                    userId: user.id,
                });
            }

            // Gerar token JWT se 2FA não estiver habilitado
            const tokenJWT = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
            res.status(200).json({ message: 'Login successful', token: tokenJWT });
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Internal server error' });
        }
    }
);

// Rota para Habilitar o 2FA
router.post('/enable-2fa', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Gerar a chave secreta do 2FA
        const secret = speakeasy.generateSecret({
            length: 20,
            name: `MyApp (${user.email})`,
        });

        // Armazenar a chave secreta no banco de dados
        user.twofa_secret = secret.base32;
        user.twofa_enabled = true;
        await user.save();

        // Gerar o código QR para o aplicativo de autenticação
        const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

        res.status(200).json({ message: '2FA enabled', qrCodeUrl });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Rota para Verificar o Código do 2FA
router.post('/verify-2fa-code', async (req, res) => {
    const { userId, code } = req.body;

    if (!userId || !code) {
        return res.status(400).json({ error: 'User ID and code are required' });
    }

    try {
        const user = await User.findByPk(userId);
        if (!user || !user.twofa_code || !user.twofa_code_expiry) {
            return res.status(400).json({ error: 'Invalid or expired 2FA code' });
        }

        // Verificar validade do código e expiração
        const now = new Date();
        if (user.twofa_code !== code || user.twofa_code_expiry < now) {
            return res.status(400).json({ error: 'Invalid or expired 2FA code' });
        }

        // Gerar token JWT após verificação bem-sucedida
        const tokenJWT = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

        // Limpar código e expiração no banco
        user.twofa_code = null;
        user.twofa_code_expiry = null;
        await user.save();

        res.status(200).json({ message: '2FA verification successful', token: tokenJWT });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Rota protegida, exige autenticação
router.get('/profile', authenticateJWT, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Rota para iniciar o login com Google
router.get('/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

// Rota de callback após a autenticação com Google
router.get('/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/dashboard'); // Redirecionar para o dashboard ou outra página
    });


// Rota de logout
router.get('/logout', (req, res) => {
    req.logout((err) => {
        if (err) return next(err);
        res.redirect('/'); // Redireciona para a home após logout
    });
});

router.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/login');
    }
    res.render('dashboard', { user: req.user });  // Envia o usuário autenticado para a view dashboard.pug
});

module.exports = router;
