const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();

const authenticateJWT = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];  // Aguardar "Bearer token"

    if (!token) {
        return res.status(403).json({ message: 'Token não fornecido' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Token inválido' });
        }
        req.user = user;  // Adiciona a informação do usuário na requisição
        next();  // Prosegue para a próxima função
    });
};

module.exports = authenticateJWT;
