const db = require("../data/db.js");
const { DataTypes } = require('sequelize');
const usuariosModel=require("../models/usuariosModel");
const productosModel=require("../models/productosModel")

const PedidosModel=db.define('pedidos',{
    usuario_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: usuariosModel,
          key: 'id',
        },
      },
      producto_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        references: {
          model: productosModel,
          key: 'id',
        },
      },
      cantidad: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      precio_total: {
        type: DataTypes.DECIMAL(10, 2),
        allowNull: false,
      },
      estado: {
        type: DataTypes.STRING,
        allowNull: false,
      },
      fecha_pedido: {
        type: DataTypes.DATE,
        defaultValue: DataTypes.NOW,
      },
      dirección_envío : {
        type: DataTypes.STRING,
        allowNull: false,
      },
      método_pago: {
        type: DataTypes.STRING,
        allowNull: false,
      },
    }, {
      timestamps: false,
      tableName: 'pedidos'

});

// Definir las relaciones
PedidosModel.belongsTo(usuariosModel, { foreignKey: 'usuario_id' }); // Un pedido pertenece a un usuario
PedidosModel.belongsTo(productosModel, { foreignKey: 'producto_id' }); // Un pedido pertenece a un producto


module.exports =PedidosModel;