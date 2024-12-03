const { DataTypes } = require('sequelize');
const sequelize = require('../config/db'); // seu arquivo de conexão com o banco


const User = sequelize.define('User', {
    id: {
        type: DataTypes.INTEGER, // ID USER
        primaryKey: true,
        autoIncrement: true,      
    },
    username: {
        type: DataTypes.STRING,  //USERNAME
        allowNull: false,
    },
    email: {
        type: DataTypes.STRING, // EMAIL
        allowNull: false,
        unique: true,
    },
    password: {
        type: DataTypes.STRING, //SENHA
        allowNull: false,
    },
    googleId: {
        type: DataTypes.STRING, //GOOGLEID
        allowNull: true, 
        unique: true,   
    },
    twofa_enabled: {
        type: DataTypes.BOOLEAN, //2FA
        defaultValue: false,
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
        defaultValue: DataTypes.NOW,//CRIADO EM
    },
    updatedAt: {
        type: DataTypes.DATE, //EDITADO EM
        defaultValue: DataTypes.NOW,
    },
    twofa_secret: {  
        type: DataTypes.STRING, //Codigo 2FA
        allowNull: true,
    },
});

// Sincroniza com o banco de dados
User.sync()
    .then(() => console.log('Tabela User criada com sucesso'))
    .catch(err => console.error('Erro ao criar tabela User:', err));

module.exports = User;
