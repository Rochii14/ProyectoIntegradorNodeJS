const {Sequelize} = require ("sequelize")
require('dotenv').config();

/*  nombre de la base de datos -  user - contraseña - {donde esta alojada?,lenguaje, puerto} */

const db = new Sequelize(process.env.DB_NAME, process.env.DB_USER, process.env.DB_PASS,{
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    dialect: "mysql",
})

module.exports= db