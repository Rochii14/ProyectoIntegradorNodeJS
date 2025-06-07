const db = require("../data/db.js");
const { DataTypes } = require('sequelize');


const ProductosModel = db.define('productos', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    imagen: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    alt: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    nombre: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    descripcion: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    precio: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: false,
    },
}, {
    timestamps: false,
    tableName: 'productos',
});

module.exports = ProductosModel;

