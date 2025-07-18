require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { User } = require('./models');

const app = express();
app.use(express.json());
 
 
// === Endpoint Registrasi Pengguna ===
app.post('/register', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    const newUser = await User.create({ email, password, role });
    res.status(201).json({ message: "User registered successfully!", userId:
newUser.id });
  } catch (error) {
    res.status(500).json({ message: "Registration failed", error: error.message
});
  }
});

// === Endpoint Login Pengguna ===
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }
    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' } // Token berlaku selama 1 jam
    );

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  } 
 
});

// Import middleware
const { authenticate, authorizeAdmin, authorizeUser } =
require('./middleware/authMiddleware'); 

// === Contoh Penerapan Middleware ===

// 1. Route untuk semua pengguna yang sudah terautentikasi (admin & user)
app.get('/profile', authenticate, (req, res) => {
  res.json({ message: `Welcome, ${req.user.email}!`, data: req.user });
});

// 2. Route HANYA untuk ADMIN
app.get('/admin/data', authenticate, authorizeAdmin, (req, res) => {
  res.json({ message: 'This is sensitive data, only for admins.' });
});

// 3. Route HANYA untuk USER BIASA
app.get('/user/orders', authenticate, authorizeUser, (req, res) => {
    res.json({ message: 'List of your orders.' });
});

// === Swagger Documentation Setup ===
const swaggerUi = require('swagger-ui-express');
const YAML = require('yamljs');
const swaggerDocument = YAML.load('./openapi.yaml');

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const PORT = process.env.PORT || 3307;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`)); 