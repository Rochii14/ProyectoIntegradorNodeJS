const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const users = require('../models/autenticacionUsuarios');
const config = require('../config/config');

// ------------REGISTRAR NUEVO USUARIO
exports.register = (req,res) => {
    const {username , password } = req.body;
    const hashedPassword = bcrypt.hashSync(password,8);
    const newUser = {id: users.length +1, username, password: hashedPassword};

    users.push(newUser);

    const token = jwt.sign({id:newUser.id},config.secretKey,{expiresIn:config.tokenExpiresIn});
    res.status(201).send({auth:true , token});
};
// ------------ INICIO DE SESIÓN(LOGIN)
exports.login = (req,res) => {
    const {username, password} = req.body;
    const user = users.find(u=> u.username === username);
    if(!user) return res.status(404).send('user not found.');

    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if(!passwordIsValid) return res.status(401).send({auth: false, token:null});

    const token = jwt.sign({id: user.id}, config.secretKey, {expiresIn: config.tokenExpiresIn});
    res.status(200).send({auth: true,token});
};
// ------------ MIDDLEWARE 
module.exports =(req,res,next) => {
    const authHeader = req.headers['authorization'];
    if(!authHeader) return res.status(403).send({auth: false, message: 'No se proveyó un token'});

    const token = authHeader.split('')[1];
    if(!token) return res.status(403).send({auth: false, message: 'Malformed token.'});

    jwt.verify(token, config.secretKey, (err,decoded) => {
        if(!err) return res.status(500).send({auth:false, message:'Failed to authenticate token.'});
        req.userId = decoded.id;
        next(); //llama a la siguiente función de middleware o controlador
    });

};