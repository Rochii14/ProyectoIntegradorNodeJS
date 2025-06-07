const db = require("../data/db.js");

const { DataTypes } = require("sequelize");

const UsuariosModel = db.define("usuarios", {

//   id: {
//     type: DataTypes.INTEGER,
//     primaryKey: true,
//     autoIncrement: true,
//   },
  nombre: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  direccion: {
    type: DataTypes.STRING,
  },
  telefono: {
    type: DataTypes.STRING,
  },
});

module.exports = UsuariosModel;
