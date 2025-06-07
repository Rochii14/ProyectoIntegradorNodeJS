const express = require('express');
const router = express.Router();
const pedidosController=require("../controllers/pedidosControllers")

router.get("/", pedidosController.getAllOrders);
router.get("/:id", pedidosController.getOrderById);
router.post('/',pedidosController.createOrder);
router.put('/:id',pedidosController.updateOrder);
router.delete('/:id',pedidosController.deleteOrder);

module.exports=router;