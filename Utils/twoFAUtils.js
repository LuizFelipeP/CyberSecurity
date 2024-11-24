const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Gera código 2FA de 6 dígitos
exports.generate2FACode = () => crypto.randomInt(100000, 999999).toString();

// Hash do código
exports.hashCode = async (code) => bcrypt.hash(code, 10);

// Verifica o código enviado
exports.verifyCode = async (receivedCode, hashedCode) => bcrypt.compare(receivedCode, hashedCode);
