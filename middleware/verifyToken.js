const jwt = require('jsonwebtoken');
const secretKey = 'messages-app'; 
function verifyToken(req, res, next) {
  // Obtener el token del encabezado de autorización
  const token = req.headers['authorization'];

  // Verificar si el token existe
  if (!token) {
    return res.status(403).json({ error: 'Token no proporcionado' });
  }

  // Verificar el token JWT
  jwt.verify(token.split(' ')[1], secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    // Si el token es válido, almacenar la información del usuario en el objeto de solicitud y continuar
    req.user = decoded;
    next();
  });
}

module.exports = verifyToken;
