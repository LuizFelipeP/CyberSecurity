const { DataTypes } = require('sequelize');
const sequelize = require('../config/db'); // seu arquivo de conexão com o banco

// Definindo o modelo User
const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER,  // ou DataTypes.UUID para UUID
        primaryKey: true,
        autoIncrement: true,      // Garante que o ID será gerado automaticamente
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    googleId: {  // Adicionando o campo googleId para armazenar a ID do Google
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,  // Para garantir que o googleId seja único
    },
    twofa_enabled: {
        type: DataTypes.BOOLEAN,
        defaultValue: false, // False por padrão; será habilitado quando o 2FA for configurado.
    },
    twofa_code: {
        type: DataTypes.STRING,
        allowNull: true, // Código 2FA enviado por e-mail
    },
    twofa_code_expiry: {
        type: DataTypes.DATE,
        allowNull: true, // Data de expiração para o código
    },
    createdAt: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
    },
    updatedAt: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
    },
    twofa_secret: {  // Adicionando o campo twofa_secret
        type: DataTypes.STRING,
        allowNull: true,
    },
});

// Sincroniza com o banco de dados
User.sync()
    .then(() => console.log('Tabela User criada com sucesso'))
    .catch(err => console.error('Erro ao criar tabela User:', err));

module.exports = User;
