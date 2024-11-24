const bcrypt = require('bcrypt');
const crypto = require('crypto');

/**
 * Gera um hash para uma senha usando bcrypt
 * @param {string} password - A senha a ser criptografada
 * @returns {Promise<string>} - O hash gerado
 */
const hashPassword = async (password) => {
    const saltRounds = 10; // Define o número de rodadas de sal
    return await bcrypt.hash(password, saltRounds);
};

/**
 * Compara uma senha com um hash usando bcrypt
 * @param {string} password - A senha fornecida pelo usuário
 * @param {string} hash - O hash armazenado no banco de dados
 * @returns {Promise<boolean>} - true se a senha for válida, caso contrário false
 */
const verifyPassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

/**
 * Gera um token seguro, útil para 2FA ou redefinição de senha
 * @param {number} length - Comprimento do token
 * @returns {string} - Token gerado
 */
const generateSecureToken = (length = 32) => {
    return crypto.randomBytes(length).toString('hex');
};

module.exports = {
    hashPassword,
    verifyPassword,
    generateSecureToken,
};
