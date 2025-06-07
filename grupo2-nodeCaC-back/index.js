const express = require('express');
const app = express();
require('dotenv').config();
const cors = require('cors');
const db = require ("./data/db.js")
const usuariosRoutes = require('./routes/usuariosRouter'); 
const productosRoutes = require('./routes/productosRouter');
const pedidosRoutes= require('./routes/pedidosRouter');

app.use(cors());
app.use(express.json());

app.use(express.static('public'));

// utiliza las rutas
app.get ("/",(req,res)=>{
  res.send ("Bienvenido")
  })

app.use('/usuarios', usuariosRoutes);
app.use('/productos', productosRoutes);
app.use('/pedidos', pedidosRoutes);

const conexionDB = async ()=>{
    try {
        await db.authenticate()
        console.log(`Conectado Ok a la Base de datos`);
    } catch (error) {
        console.log(`Hay un error y es el siguiente : ${error}`);
    }
}


// Iniciar el servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  conexionDB()
  console.log(`Servidor en ejecución en el puerto ${PORT}`);
});
