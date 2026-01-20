// KenyaPolitics Predict - Complete Platform
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// Database Connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
  console.error('❌ ERROR: MONGODB_URI is not defined in environment variables');
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI);
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => {
  console.error('❌ MongoDB Connection Error:', err.message);
  process.exit(1);
});

// Simple User Schema
const User = mongoose.model('User', new mongoose.Schema({
  phone: { type: String, unique: true },
  password: String,
  balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
}));

// M-Pesa Service
class MpesaService {
  constructor() {
    this.baseUrl = 'https://sandbox.safaricom.co.ke';
    this.consumerKey = process.env.MPESA_CONSUMER_KEY;
    this.consumerSecret = process.env.MPESA_CONSUMER_SECRET;
    this.passkey = process.env.MPESA_PASSKEY;
    this.shortcode = process.env.MPESA_SHORTCODE || '174379';
  }

  async getAccessToken() {
    try {
      const auth = Buffer.from(`${this.consumerKey}:${this.consumerSecret}`).toString('base64');
      const response = await axios.get(
        `${this.baseUrl}/oauth/v1/generate?grant_type=client_credentials`,
        { headers: { Authorization: `Basic ${auth}` } }
      );
      return response.data.access_token;
    } catch (error) {
      console.error('Token Error:', error.message);
      throw error;
    }
  }
}

// API Routes
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    message: 'KenyaPolitics Predict API is running',
    timestamp: new Date().toISOString()
  });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    if (!phone || !password) {
      return res.status(400).json({ error: 'Phone and password required' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ phone, password: hashedPassword });
    
    // Create token
    const token = jwt.sign(
      { userId: user._id, phone: user.phone },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      user: { id: user._id, phone: user.phone, balance: user.balance },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    const user = await User.findOne({ phone });
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { userId: user._id, phone: user.phone },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      user: { id: user._id, phone: user.phone, balance: user.balance },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// M-Pesa callback (simplified)
app.post('/api/mpesa/callback', (req, res) => {
  console.log('M-Pesa Callback:', JSON.stringify(req.body, null, 2));
  res.json({ ResultCode: 0, ResultDesc: 'Success' });
});

// Homepage
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>KenyaPolitics Predict</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <div class="container mx-auto px-4 py-16 text-center">
        <h1 class="text-4xl font-bold text-green-600 mb-4">KenyaPolitics Predict</h1>
        <p class="text-xl text-gray-600 mb-8">Political Prediction Market for Kenyan Elections</p>
        <div class="bg-white rounded-lg shadow p-8 max-w-md mx-auto">
            <h2 class="text-2xl font-bold mb-6">API Status: <span class="text-green-500">✓ Running</span></h2>
            <div class="text-left space-y-3">
                <p><strong>Base URL:</strong> ${process.env.BASE_URL || 'http://localhost:3000'}</p>
                <p><strong>Health Check:</strong> <a href="/health" class="text-blue-500">/health</a></p>
                <p><strong>Registration:</strong> POST /api/auth/register</p>
                <p><strong>Login:</strong> POST /api/auth/login</p>
            </div>
        </div>
    </div>
</body>
</html>
  `);
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
🚀 KenyaPolitics Predict Server Started
📍 Port: ${PORT}
🌐 URL: ${process.env.BASE_URL || `http://localhost:${PORT}`}
📊 Health: ${process.env.BASE_URL || `http://localhost:${PORT}`}/health
  `);
});
