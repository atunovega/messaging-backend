const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const http = require('http');
const socketIo = require('socket.io');
const passport = require('passport');
const session = require('express-session');
const LocalStrategy = require('passport-local').Strategy;

const jwt = require('jsonwebtoken');
const verifyToken = require('./middleware/verifyToken');
const secretKey = 'messages-app'; // Clave secreta para firmar los tokens TODO:Variable de entorno

// Función para generar un token JWT con la información del usuario
function generateToken(user) {
    return jwt.sign(user, secretKey, { expiresIn: '1h' });
}


let users = [
    { username: "Juan", password: "Aa123" },
    { username: "Pedro", password: "Aa123" },
    { username: "Pablo", password: "Aa123" }

]; // Almacenamiento en memoria para usuarios
let messages = []; // Almacenamiento en memoria para mensajes

const app = express();
app.use(session({
    secret: 'messages-app',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: '*', // Permitir conexiones desde cualquier origen
        methods: ['GET', 'POST'] // Métodos permitidos
    }
});



passport.use(new LocalStrategy(
    (username, password, done) => {
        // Buscar el usuario 
        const user = users.find(user => user.username === username);

        if (!user) {
            return done(null, { status: "error", message: 'User not found' });
        }

        if (user.password !== password) {
            return done(null, { status: "error", message: 'Incorrect password' });
        }

        // Si las credenciales son válidas, generar y devolver un token JWT
        const token = generateToken({ username: user?.username });
        return done(null, { user, token }); // Pasar el usuario y el token
    }
));

// Serializar y deserializar usuarios para almacenar en sesión
passport.serializeUser((user, done) => {
    done(null, user.username);
});

passport.deserializeUser((username, done) => {
    const user = users.find(user => user.username === username);
    done(null, user);
});


app.use(cors());
app.use(bodyParser.json());

io.use((socket, next) => {
    const token = socket?.handshake?.auth?.token;
    if (!token) {
        return next(new Error('Token no proporcionado'));
    }

    // Verificar el token JWT
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return next(new Error('Token inválido'));
        }

        // Si el token es válido, almacenar la información del usuario en el socket y continuar
        socket.decoded = decoded;
        next();
    });
});

io.on('connection', (socket) => {
    console.log(`Nuevo cliente conectado - ID: ${socket.id}`);
    console.log('Usuario autenticado:', socket.decoded);
});

// Ruta para registrar un nuevo usuario
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    // Verificar si el usuario ya existe
    if (users.find((user) => user.username === username)) {
        return res.status(201).json({ status: "error", message: 'Username already exists' });
    }
    users.push({ username, password });
    res.status(201).json({ status: "success", message: 'User registered successfully' });
});

// Ruta para iniciar sesión (autenticación)
app.post('/login',
    passport.authenticate('local', { session: false }),
    (req, res) => {
        let status = "success"

        if (req.user.status == "error") {
            status = "error"
        }
        res.status(200).json({ status, token: req.user.token, username: req.user?.user?.username, message: req.user?.message }); // Devolver el token al cliente
    }
);


// Ruta para enviar un mensaje
app.post('/send-message', verifyToken, (req, res) => {
    const sender = req.user.username
    const { receiver, message } = req.body;
    messages.push({ sender, receiver, message });

    // Emisión del mensaje solo al destinatario mediante Socket.IO
    let recipientSocket;
    for (const [socketId, socket] of io.of('/').sockets) {
        if (socket.decoded.username === receiver) {
            recipientSocket = socket;
            break;
        }
    }

    if (recipientSocket) {
        recipientSocket.emit('new-message', { sender, message });
    }
    res.status(201).json({ status: "success", message: 'Message sent successfully' });
});

// Ruta para obtener mensajes para un usuario autenticado y su interlocutor
app.get('/messages/:username', verifyToken, (req, res) => {
    const usernameParams = req.params?.username;
    const username = req.user.username
    const userMessages = messages.filter((msg) => (msg.receiver === username && msg.sender === usernameParams) || (msg.sender === username && msg.receiver === usernameParams));
    res.status(200).json({ messages: userMessages });
});

//Ruta para obtener los usuarios con los cuales chatear
app.get('/users', verifyToken, (req, res) => {
    const username = req.user.username;
    const usersToMe = users.filter((user) => user.username != username).map(user => ({ username: user.username }));
    res.status(200).json({ users: usersToMe });
});

const PORT = 3001;
server.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
