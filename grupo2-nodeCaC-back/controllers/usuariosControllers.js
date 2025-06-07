const User = require('../models/usuariosModel');
const Order=require('../models/pedidosModel')

exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.findAll();
    res.json(users);
  } catch (error) {
    res.json({message:error.message}) 
  }
};

exports.getUserById = async (req, res) => { 
  try {
    const user = await User.findByPk(req.params.id)
    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    res.json(user);
  } catch (error) {
    res.json({message:error.message}) 
  }
};

exports.createUser = async (req, res) => {
  try {
  await User.create(req.body)
  res.json({"message": "Usuario creado correctamente"})
} catch (error) {
  res.json({message:error.message}) 
}
};
 

exports.updateUser = async (req, res) => {
  try {
    await User.update(req.body,{
      where :{id:req.params.id}
    })
    res.json({ message: 'Usuario actualizado exitosamente' });
  } catch (error) {
    res.json({message:error.message}) 
  }
};


exports.deleteUser = async (req, res) => {
   try {
    await User.destroy({where :{id:req.params.id}});
    res.json({ message: 'Usuario eliminado exitosamente' });
  } catch (error) {
    res.json({message:error.message}) 
  }
};

// Método para obtener los pedidos de un usuario por su ID Relación 1 a muchos
exports.getPedidosByUserId = async (req, res) => {
  const userId = req.params.id;

  try {
    const orders = await Order.findAll({
      where: { usuario_id: userId }   //sql=SELECT * FROM pedidos WHERE usuario_id = 3;
    });
    res.json(orders);
  } catch (error) {
    console.error('Error al obtener los pedidos del usuario:', error);
    res.status(500).json({ error: 'Error al obtener los pedidos del usuario' });
  }
};