module.exports = {
    secret: process.env.JWT_SECRET || 'seu-segredo-aqui',  // Carrega o segredo do JWT do arquivo .env
    expiresIn: '30s'  // Expiração do token em 1 hora
};
