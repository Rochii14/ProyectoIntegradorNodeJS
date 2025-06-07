const Product= require('../models/productosModel');

exports.getAllProducts = async (req, res) => {
    try {
      const products = await Product.findAll();
      res.json(products);
    } catch (error) {
      res.json({message:error.message}) 
    }
  };

  exports.getProductById = async (req, res) => {
    const { id } = req.params;
    try {
      const product = await Product.findByPk(id);
      if (!product) {
        return res.status(404).json({ message: 'Producto no encontrado' });
      }
      res.json(product);
    } catch (error) {
      res.json({message:error.message}) 
    }
  };

  exports.createProduct = async (req, res) => {
    try {
    await Product.create(req.body)
    res.json({"message": "Producto creado correctamente"})
  } catch (error) {
    res.json({message:error.message}) 
  }
  };

  exports.updateProduct = async (req, res) => {
    try {
      await Product.update(req.body,{
        where :{id:req.params.id}
      })
      res.json({ message: 'Producto actualizado exitosamente' });
    } catch (error) {
      res.json({message:error.message}) 
    }
  };
   
  exports.deleteProduct = async (req, res) => {
    try {
     await Product.destroy({where :{id:req.params.id}});
     res.json({ message: 'Producto eliminado exitosamente' });
   } catch (error) {
     res.json({message:error.message}) 
   }
 };

