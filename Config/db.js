require('dotenv').config();
const { Sequelize } = require('sequelize');

const sequelize = new Sequelize(process.env.DB_URL, {
    dialect: 'postgres',
    logging: false,
});

sequelize.authenticate()
    .then(() => console.log('Connected to the database successfully!'))
    .catch((error) => console.error('Unable to connect to the database:', error));

module.exports = sequelize;