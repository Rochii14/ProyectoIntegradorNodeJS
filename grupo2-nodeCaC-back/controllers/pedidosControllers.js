const Order = require('../models/pedidosModel');
const productosModel = require('../models/productosModel');

exports.getAllOrders= async(req, res)=>{
    try {
        const orders=await Order.findAll();
        res.json(orders)
    } catch (error) {
        res.json({message:error.message})
    }
}

exports.getOrderById= async(req, res)=>{
    try {
        const order=await Order.findByPk(req.params.id)
        res.json(order);
    } catch (error) {
        res.json({message:error.message})
        
    }
}

exports.createOrder = async (req, res) => {
    try {
        // Obtener el id del producto y la cantidad del cuerpo de la solicitud
        const { producto_id, cantidad } = req.body;

        // Obtener el producto de la base de datos para obtener el precio unitario
        const producto = await productosModel.findByPk(producto_id);
        if (!producto) {
            return res.status(404).json({ message: "Producto no encontrado" });
        }

        // Calcular el precio total
        const precio_total = producto.precio * cantidad;

        // Crear el pedido con el precio total calculado
        const newOrder = {
            ...req.body,
            precio_total
        };

        await Order.create(newOrder);
        res.json({ message: "Pedido creado correctamente" });
    } catch (error) {
        res.json({ message: error.message });
    }
};

exports.updateOrder=async(req,res)=>{
    try {
        await Order.update(req.body,{
            where :{id:req.params.id}
        })
        res.json({ message: 'Producto actualizado exitosamente' });
    } catch (error) {
        res.json({message:error.message})
    }
}

exports.deleteOrder=async(req,res)=>{
    try {
        await Order.destroy({where :{id:req.params.id}})
        res.json({ message: 'Pedido eliminado exitosamente' });
    } catch (error) {
        res.json({message:error.message}) 
    }
}