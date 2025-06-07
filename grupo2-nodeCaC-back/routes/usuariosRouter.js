const express = require('express');
const router = express.Router();
const usuariosController = require('../controllers/usuariosControllers');

router.get('/', usuariosController.getAllUsers);
router.get('/:id', usuariosController.getUserById);
router.post('/', usuariosController.createUser);
router.put('/:id', usuariosController.updateUser);
router.delete('/:id', usuariosController.deleteUser);

//para obtener los pedidos de 1 usuario
router.get('/:id/pedidos', usuariosController.getPedidosByUserId);

module.exports = router;