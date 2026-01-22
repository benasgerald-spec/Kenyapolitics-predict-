// KenyaPolitics Predict - Complete Platform (Fixed Version)
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ========== MIDDLEWARE ==========
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// ========== DATABASE CONNECTION ==========
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ ERROR: MONGODB_URI is not defined in environment variables');
  process.exit(1);
}

// FIXED: Removed the stray period that caused "SyntaxError: Unexpected token '.'"
mongoose.connect(MONGODB_URI)
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// ========== DATABASE SCHEMAS ==========
const userSchema = new mongoose.Schema({
  phone: { type: String, unique: true },
  password: String,
  balance: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ========== M-PESA SERVICE ==========
class MpesaService {
  constructor() {
    this.baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://api.safaricom.co.ke' 
      : 'https://sandbox.safaricom.co.ke';
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
        { 
          headers: { Authorization: `Basic ${auth}` },
          timeout: 10000
        }
      );
      return response.data.access_token;
    } catch (error) {
      console.error('❌ M-Pesa Token Error:', error.message);
      throw new Error(`Failed to get M-Pesa token: ${error.message}`);
    }
  }

  async initiateSTKPush(phone, amount, accountRef) {
    try {
      const token = await this.getAccessToken();
      const timestamp = new Date()
        .toISOString()
        .replace(/[^0-9]/g, '')
        .slice(0, 14);
      
      const password = Buffer.from(
        `${this.shortcode}${this.passkey}${timestamp}`
      ).toString('base64');
      
      // Format phone: 07... -> 2547...
      const formattedPhone = phone.startsWith('0') ? `254${phone.substring(1)}` : phone;
      
      const response = await axios.post(
        `${this.baseUrl}/mpesa/stkpush/v1/processrequest`,
        {
          BusinessShortCode: this.shortcode,
          Password: password,
          Timestamp: timestamp,
          TransactionType: 'CustomerPayBillOnline',
          Amount: amount,
          PartyA: formattedPhone,
          PartyB: this.shortcode,
          PhoneNumber: formattedPhone,
          CallBackURL: `${process.env.BASE_URL || 'http://localhost:3000'}/api/mpesa/callback`,
          AccountReference: accountRef,
          TransactionDesc: 'KenyaPolitics Deposit'
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          timeout: 30000
        }
      );
      
      return { success: true, data: response.data };
    } catch (error) {
      console.error('❌ M-Pesa STK Push Error:', error.message);
      return {
        success: false,
        error: error.response?.data?.errorMessage || error.message
      };
    }
  }
}

const mpesaService = new MpesaService();

// ========== API ROUTES ==========

// Health Check
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  res.json({ 
    status: 'ok', 
    message: 'KenyaPolitics Predict API is running',
    database: dbStatus,
    timestamp: new Date().toISOString()
  });
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    if (!phone || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone and password are required' 
      });
    }
    
    // Validate Kenyan phone format
    if (!phone.match(/^(07|01)\d{8}$/)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid Kenyan phone number. Use format: 07XXXXXXXX or 01XXXXXXXX' 
      });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ phone });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: 'User with this phone number already exists' 
      });
    }
    
    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ 
      phone, 
      password: hashedPassword 
    });
    
    // Create JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        phone: user.phone 
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      user: { 
        id: user._id, 
        phone: user.phone, 
        balance: user.balance 
      },
      token
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Registration failed. Please try again.' 
    });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    
    if (!phone || !password) {
      return res.status(400).json({ 
        success: false,
        error: 'Phone and password are required' 
      });
    }
    
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid phone number or password' 
      });
    }
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ 
        success: false,
        error: 'Invalid phone number or password' 
      });
    }
    
    const token = jwt.sign(
      { 
        userId: user._id, 
        phone: user.phone 
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Login successful',
      user: { 
        id: user._id, 
        phone: user.phone, 
        balance: user.balance 
      },
      token
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Login failed. Please try again.' 
    });
  }
});

// M-Pesa Deposit
app.post('/api/mpesa/deposit', async (req, res) => {
  try {
    const { phone, amount } = req.body;
    
    if (!phone || !amount) {
      return res.status(400).json({
        success: false,
        error: 'Phone and amount are required'
      });
    }
    
    if (amount < 10 || amount > 70000) {
      return res.status(400).json({
        success: false,
        error: 'Amount must be between KSh 10 and KSh 70,000'
      });
    }
    
    if (!phone.match(/^(07|01)\d{8}$/)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid Kenyan phone number'
      });
    }
    
    const result = await mpesaService.initiateSTKPush(
      phone, 
      amount, 
      `DEP${Date.now()}`
    );
    
    if (!result.success) {
      return res.status(500).json({
        success: false,
        error: result.error || 'Failed to initiate M-Pesa payment'
      });
    }
    
    res.json({
      success: true,
      message: 'M-Pesa payment request sent to your phone',
      data: {
        requestId: result.data.CheckoutRequestID,
        amount: amount,
        phone: phone
      }
    });
  } catch (error) {
    console.error('❌ Deposit error:', error);
    res.status(500).json({
      success: false,
      error: 'Deposit failed. Please try again.'
    });
  }
});

// M-Pesa Callback (Webhook)
app.post('/api/mpesa/callback', async (req, res) => {
  console.log('📞 M-Pesa Callback Received:', JSON.stringify(req.body, null, 2));
  
  try {
    const callbackData = req.body;
    
    // Always respond immediately to M-Pesa
    res.json({
      ResultCode: 0,
      ResultDesc: "Success"
    });
    
    // Process callback asynchronously
    if (callbackData.Body && callbackData.Body.stkCallback) {
      const stkCallback = callbackData.Body.stkCallback;
      
      if (stkCallback.ResultCode === 0) {
        // Transaction successful
        console.log('✅ M-Pesa Transaction Successful');
        
        // Extract transaction details
        const metadata = stkCallback.CallbackMetadata.Item;
        const amount = metadata.find(item => item.Name === 'Amount')?.Value;
        const mpesaCode = metadata.find(item => item.Name === 'MpesaReceiptNumber')?.Value;
        const phone = metadata.find(item => item.Name === 'PhoneNumber')?.Value;
        
        console.log(`💰 Transaction: Amount=${amount}, Receipt=${mpesaCode}, Phone=${phone}`);
        
        // TODO: Update user balance in database
        // Find user by phone and update their balance
      } else {
        // Transaction failed
        console.error('❌ M-Pesa Transaction Failed:', stkCallback.ResultDesc);
      }
    }
  } catch (error) {
    console.error('❌ Callback processing error:', error);
  }
});

// User Profile
app.get('/api/user/profile', async (req, res) => {
  try {
    // This would require authentication middleware
    // For now, return a placeholder response
    res.json({
      success: true,
      message: 'User profile endpoint',
      note: 'Add authentication middleware to protect this route'
    });
  } catch (error) {
    console.error('❌ Profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch profile'
    });
  }
});

// ========== FRONTEND ROUTES ==========
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>KenyaPolitics Predict</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #006600 0%, #BB0000 100%);
        }
        .btn-primary {
            background: linear-gradient(135deg, #006600 0%, #BB0000 100%);
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 102, 0, 0.3);
        }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Navigation -->
    <nav class="bg-white shadow-lg">
        <div class="container mx-auto px-4 py-4">
            <div class="flex justify-between items-center">
                <div class="flex items-center space-x-2">
                    <div class="w-10 h-10 bg-gradient-to-r from-green-600 to-red-600 rounded-lg"></div>
                    <span class="text-2xl font-bold text-gray-800">KenyaPolitics Predict</span>
                </div>
                <div class="flex items-center space-x-6">
                    <a href="#features" class="text-gray-700 hover:text-green-600 font-medium">Features</a>
                    <a href="#markets" class="text-gray-700 hover:text-green-600 font-medium">Markets</a>
                    <button onclick="alert('Login modal will open here')" class="btn-primary">Login / Register</button>
                </div>
            </div>
        </div>
    </nav>

    <!-- Hero Section -->
    <section class="gradient-bg text-white py-20">
        <div class="container mx-auto px-4 text-center">
            <h1 class="text-5xl font-bold mb-6">Predict Kenyan Politics</h1>
            <p class="text-xl mb-8 max-w-2xl mx-auto">
                Trade on election outcomes, cabinet decisions, and political events.
                Turn your political insight into opportunity.
            </p>
            <div class="flex gap-4 justify-center">
                <button onclick="alert('Registration modal will open here')" 
                        class="bg-white text-green-700 px-8 py-3 rounded-lg font-semibold hover:bg-gray-100 transition">
                    Get Started Free
                </button>
                <a href="#markets" 
                   class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white/10 transition">
                    Browse Markets
                </a>
            </div>
        </div>
    </section>

    <!-- Features -->
    <section id="features" class="py-16">
        <div class="container mx-auto px-4">
            <h2 class="text-3xl font-bold text-center mb-12">How It Works</h2>
            <div class="grid md:grid-cols-3 gap-8">
                <div class="text-center p-6">
                    <div class="text-4xl mb-4">💰</div>
                    <h3 class="text-xl font-bold mb-2">Deposit with M-Pesa</h3>
                    <p class="text-gray-600">Fund your account instantly using M-Pesa. Secure and trusted.</p>
                </div>
                <div class="text-center p-6">
                    <div class="text-4xl mb-4">📈</div>
                    <h3 class="text-xl font-bold mb-2">Trade Predictions</h3>
                    <p class="text-gray-600">Buy YES or NO shares on political events. Prices update in real-time.</p>
                </div>
                <div class="text-center p-6">
                    <div class="text-4xl mb-4">🏆</div>
                    <h3 class="text-xl font-bold mb-2">Win When Right</h3>
                    <p class="text-gray-600">If your prediction is correct, you profit. Withdraw anytime via M-Pesa.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- API Status -->
    <section class="bg-gray-100 py-12">
        <div class="container mx-auto px-4">
            <h2 class="text-2xl font-bold text-center mb-8">API Status</h2>
            <div class="bg-white rounded-lg shadow p-8 max-w-2xl mx-auto">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div class="text-center p-4 border rounded-lg">
                        <div class="text-2xl font-bold text-green-600">/health</div>
                        <p class="text-gray-600">Health Check Endpoint</p>
                        <a href="/health" class="text-blue-500 text-sm">Test Now →</a>
                    </div>
                    <div class="text-center p-4 border rounded-lg">
                        <div class="text-2xl font-bold text-blue-600">/api/auth/*</div>
                        <p class="text-gray-600">Authentication Endpoints</p>
                        <p class="text-gray-500 text-sm">Register, Login</p>
                    </div>
                </div>
                <div class="mt-6 p-4 bg-blue-50 rounded-lg">
                    <p class="text-sm text-blue-800">
                        <i class="fas fa-info-circle mr-2"></i>
                        <strong>Base URL:</strong> <span id="baseUrl">${process.env.BASE_URL || 'http://localhost:3000'}</span>
                    </p>
                </div>
            </div>
        </div>
    </section>

    <footer class="bg-gray-800 text-white py-8 mt-16">
        <div class="container mx-auto px-4 text-center">
            <p>© ${new Date().getFullYear()} KenyaPolitics Predict. All rights reserved.</p>
            <p class="text-gray-400 text-sm mt-2">
                This platform is for informational purposes only. Trading involves risk.
                Users must be 18+ and comply with Kenyan regulations.
            </p>
            <p class="text-gray-400 text-xs mt-4">
                <span class="text-green-400">●</span> API Status: Operational
            </p>
        </div>
    </footer>

    <script>
        // Simple frontend interactivity
        document.addEventListener('DOMContentLoaded', function() {
            console.log('KenyaPolitics Predict frontend loaded');
        });
    </script>
</body>
</html>
  `);
});

// ========== ERROR HANDLING ==========
// 404 - Not Found
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.url
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔥 Server Error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ========== SERVER STARTUP ==========
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════╗
║      🚀 KenyaPolitics Predict Platform Started!     ║
╠══════════════════════════════════════════════════════╣
║  🌐 Server running on: http://localhost:${PORT}      ║
║  📊 Health Check: http://localhost:${PORT}/health    ║
║  🗄️  Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}          ║
║  🔧 Environment: ${process.env.NODE_ENV || 'development'} ║
╚══════════════════════════════════════════════════════╝
  `);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Received SIGINT. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed.');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed.');
      process.exit(0);
    });
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Received SIGTERM. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed.');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed.');
      process.exit(0);
    });
  });
});
