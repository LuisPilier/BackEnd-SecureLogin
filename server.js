const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json());
app.use(cors()); // Habilitar CORS para todas las solicitudes

const db = new sqlite3.Database('./users.db');

// Crear tabla de usuarios si no existe
db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)');
});

// Middleware para verificar token JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(401).json({ error: 'Token no proporcionado' });
    }

    jwt.verify(token.split(' ')[1], 'secretkey', (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.username = decoded.username;
        req.role = decoded.role;
        next();
    });
};

// Ruta de inicio de sesión
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
            if (!row) {
                return res.status(401).json({ error: 'Nombre de usuario o contraseña inválidos' });
            }
            const passwordMatch = await bcrypt.compare(password, row.password);
            if (!passwordMatch) {
                return res.status(401).json({ error: 'Nombre de usuario o contraseña inválidos' });
            }
            const token = jwt.sign({ username: row.username, role: row.role }, 'secretkey');
            console.log(`Usuario '${username}' ha iniciado sesión`); // Registro en consola
            res.status(200).json({ token });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Ruta restringida protegida por el token JWT
app.get('/restricted-route', verifyToken, (req, res) => {
    const { role } = req;
    if (role === 'admin') {
        // Acciones para administradores
    } else if (role === 'supervisor') {
        // Acciones para supervisores
    } else {
        res.status(403).json({ error: 'Acceso prohibido' });
    }
});

app.listen(PORT, () => {
    console.log(`El servidor se está ejecutando en el puerto ${PORT}`);
});
