const jwt = require('jsonwebtoken');

const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Format: "Bearer TOKEN"

    if (!token) {
        return res.status(401).json({
            message: 'Access denied. No token provided.'
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid token.' }); // Token tidak valid atau kedaluwarsa
        }
        req.user = decoded; // Simpan payload token ke request
        next();
    });
};

// 2. Middleware OTORISASI: Cek apakah user adalah 'admin'
const authorizeAdmin = (req, res, next) => {

    if (req.user.role !== 'admin') {
        return res.status(403).json({
            message: 'Forbidden. Admin access required.'
        });
    }
    next();
};

// 3. Middleware OTORISASI: Cek apakah user adalah 'user' biasa
const authorizeUser = (req, res, next) => {
    if (req.user.role !== 'user') {
        return res.status(403).json({
            message: 'Forbidden. User access required.'
        });
    }
    next();
};

module.exports = {
    authenticate,
    authorizeAdmin,
    authorizeUser
};
