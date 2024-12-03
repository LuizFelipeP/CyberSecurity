const rateLimit = require('express-rate-limit');

// Middleware para limitar tentativas de login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // Janela de 15 minutos
    max: 5, // Limite de 5 requisições
    message: { message: 'Muitas tentativas falhas. Tente novamente após 15 minutos.' },
    standardHeaders: true, // Retorna informações no cabeçalho `RateLimit-*`
    legacyHeaders: false, // Desativa cabeçalhos `X-RateLimit-*` legados
    keyGenerator: (req) => req.ip, // Limita por IP
    handler: (req, res, next, options) => {
        console.error(`Tentativas excedidas para IP: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    },
});

module.exports = loginLimiter;
