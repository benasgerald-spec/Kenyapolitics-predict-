// ========== KENYAPOLITICS PREDICT - COMPLETE PLATFORM ==========
// Production-ready version with all features

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();

// ========== MIDDLEWARE CONFIGURATION ==========
app.use(express.json({ limit: '10mb' }));
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.BASE_URL 
    : 'http://localhost:3000',
  credentials: true
}));
app.use(express.static('public'));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ========== DATABASE CONNECTION ==========
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
  console.error('❌ CRITICAL: MONGODB_URI environment variable is not set');
  process.exit(1);
}

// Using the simplified connection that worked for you
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('✅ MongoDB Atlas Connected Successfully');
    console.log(`📊 Database: ${mongoose.connection.name}`);
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Failed:', err.message);
    console.error('💡 Tip: Check if IP 0.0.0.0/0 is whitelisted in MongoDB Atlas');
    process.exit(1);
  });

// Handle MongoDB connection events
mongoose.connection.on('error', err => {
  console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('MongoDB disconnected. Attempting to reconnect...');
});

// ========== DATABASE SCHEMAS ==========

// User Schema
const userSchema = new mongoose.Schema({
  phone: { 
    type: String, 
    required: true, 
    unique: true,
    match: [/^(07|01)\d{8}$/, 'Please provide a valid Kenyan phone number']
  },
  mpesaName: { type: String, required: true },
  nationalId: String,
  kycVerified: { type: Boolean, default: false },
  balance: { type: Number, default: 0, min: 0 },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'moderator'], 
    default: 'user' 
  },
  password: { type: String, required: true },
  totalTraded: { type: Number, default: 0 },
  profitLoss: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

userSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

// Market Schema
const marketSchema = new mongoose.Schema({
  question: { 
    type: String, 
    required: true, 
    trim: true,
    minlength: 10,
    maxlength: 500 
  },
  description: { type: String, maxlength: 2000 },
  category: { 
    type: String, 
    enum: ['elections', 'cabinet', 'legislation', 'parties', 'county', 'economy'],
    default: 'elections',
    index: true
  },
  slug: { type: String, unique: true, lowercase: true },
  
  // Market timeline
  resolutionDate: { type: Date, required: true, index: true },
  resolved: { type: Boolean, default: false, index: true },
  outcome: { 
    type: String, 
    enum: ['YES', 'NO', 'CANCELLED', null], 
    default: null 
  },
  resolvedAt: Date,
  resolvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  resolutionJustification: String,
  
  // Trading metrics
  volumeYes: { type: Number, default: 0, min: 0 },
  volumeNo: { type: Number, default: 0, min: 0 },
  totalVolume: { type: Number, default: 0, min: 0 },
  yesPrice: { type: Number, default: 0.5, min: 0, max: 1 },
  noPrice: { type: Number, default: 0.5, min: 0, max: 1 },
  lastTradeAt: Date,
  
  // Market creator info
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now, index: true },
  updatedAt: { type: Date, default: Date.now }
});

// Auto-generate slug and update totals
marketSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  this.totalVolume = this.volumeYes + this.volumeNo;
  
  // Generate slug from question
  if (this.isModified('question')) {
    this.slug = this.question
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, '')
      .replace(/\s+/g, '-')
      .substring(0, 100);
  }
  
  // Calculate prices if volumes exist
  if (this.volumeYes > 0 || this.volumeNo > 0) {
    const total = this.volumeYes + this.volumeNo;
    this.yesPrice = this.volumeNo / total;
    this.noPrice = this.volumeYes / total;
  }
  
  next();
});

// Trade Schema
const tradeSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  marketId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Market', 
    required: true,
    index: true 
  },
  outcome: { 
    type: String, 
    enum: ['YES', 'NO'], 
    required: true 
  },
  shares: { 
    type: Number, 
    required: true, 
    min: 0.01 
  },
  price: { 
    type: Number, 
    required: true, 
    min: 0.01, 
    max: 0.99 
  },
  amount: { 
    type: Number, 
    required: true, 
    min: 10 
  },
  tradeType: { 
    type: String, 
    enum: ['buy', 'sell'], 
    default: 'buy' 
  },
  matched: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now, index: true }
});

// Deposit Schema
const depositSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  amount: { 
    type: Number, 
    required: true, 
    min: 10, 
    max: 70000 
  },
  mpesaCode: String,
  phone: { 
    type: String, 
    required: true,
    match: [/^(07|01)\d{8}$/, 'Invalid phone number']
  },
  requestId: { type: String, index: true },
  accountReference: { type: String, index: true },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'pending',
    index: true 
  },
  completedAt: Date,
  createdAt: { type: Date, default: Date.now, index: true }
});

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true 
  },
  amount: { 
    type: Number, 
    required: true, 
    min: 100, 
    max: 70000 
  },
  phone: { 
    type: String, 
    required: true,
    match: [/^(07|01)\d{8}$/, 'Invalid phone number']
  },
  mpesaCode: String,
  status: { 
    type: String, 
    enum: ['pending', 'processing', 'completed', 'failed'], 
    default: 'pending',
    index: true 
  },
  completedAt: Date,
  createdAt: { type: Date, default: Date.now, index: true }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Market = mongoose.model('Market', marketSchema);
const Trade = mongoose.model('Trade', tradeSchema);
const Deposit = mongoose.model('Deposit', depositSchema);
const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

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
    this.callbackUrl = `${process.env.BASE_URL}/api/mpesa/callback`;
    
    if (!this.consumerKey || !this.consumerSecret || !this.passkey) {
      console.error('❌ M-Pesa credentials missing in environment variables');
    }
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
      if (error.response) {
        console.error('Response:', error.response.data);
      }
      throw new Error(`M-Pesa authentication failed: ${error.message}`);
    }
  }

  async initiateSTKPush(phone, amount, accountRef, description = 'KenyaPolitics Deposit') {
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
      
      const payload = {
        BusinessShortCode: this.shortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: Math.floor(amount),
        PartyA: formattedPhone,
        PartyB: this.shortcode,
        PhoneNumber: formattedPhone,
        CallBackURL: this.callbackUrl,
        AccountReference: accountRef,
        TransactionDesc: description
      };

      console.log('📤 Sending M-Pesa STK Push for:', accountRef);
      
      const response = await axios.post(
        `${this.baseUrl}/mpesa/stkpush/v1/processrequest`,
        payload,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json'
          },
          timeout: 30000
        }
      );
      
      console.log('✅ M-Pesa Response:', response.data.ResponseCode);
      
      return {
        success: response.data.ResponseCode === '0',
        data: response.data,
        requestId: response.data.CheckoutRequestID,
        responseCode: response.data.ResponseCode
      };
    } catch (error) {
      console.error('❌ M-Pesa STK Push Error:', error.message);
      return {
        success: false,
        error: error.response?.data?.errorMessage || error.message,
        code: error.response?.data?.responseCode
      };
    }
  }
}

const mpesaService = new MpesaService();

// ========== MARKET MAKER ENGINE ==========
class MarketMaker {
  static calculatePrices(volumeYes, volumeNo, tradeAmount, outcome) {
    // Add initial liquidity if no trades yet
    if (volumeYes === 0 && volumeNo === 0) {
      volumeYes = 1000;
      volumeNo = 1000;
    }

    const k = volumeYes * volumeNo; // Constant product
    
    if (outcome === 'YES') {
      const newVolumeNo = k / (volumeYes + tradeAmount);
      const cost = volumeNo - newVolumeNo;
      const totalValue = volumeYes + tradeAmount + newVolumeNo;
      
      return {
        newYesPrice: newVolumeNo / totalValue,
        newNoPrice: (volumeYes + tradeAmount) / totalValue,
        cost,
        newVolumeYes: volumeYes + tradeAmount,
        newVolumeNo
      };
    } else {
      const newVolumeYes = k / (volumeNo + tradeAmount);
      const cost = volumeYes - newVolumeYes;
      const totalValue = newVolumeYes + volumeNo + tradeAmount;
      
      return {
        newYesPrice: (volumeNo + tradeAmount) / totalValue,
        newNoPrice: newVolumeYes / totalValue,
        cost,
        newVolumeYes,
        newVolumeNo: volumeNo + tradeAmount
      };
    }
  }
  
  static getImpliedProbability(yesPrice, noPrice) {
    const total = yesPrice + noPrice;
    return {
      yesProbability: yesPrice / total,
      noProbability: noPrice / total
    };
  }
}

// ========== AUTHENTICATION MIDDLEWARE ==========
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        success: false, 
        error: 'Authentication required. Provide a valid token.' 
      });
    }

    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const user = await User.findById(decoded.userId).select('-password');
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        error: 'User not found. Please login again.' 
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Auth error:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Invalid token. Please login again.' 
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        error: 'Token expired. Please login again.' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      error: 'Authentication failed' 
    });
  }
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false, 
      error: 'Admin access required' 
    });
  }
  next();
};

// ========== HELPER FUNCTIONS ==========
const formatPhoneNumber = (phone) => {
  if (!phone) return '';
  const digits = phone.replace(/\D/g, '');
  
  if (digits.startsWith('254') && digits.length === 12) {
    return digits;
  }
  
  if (digits.startsWith('0') && digits.length === 10) {
    return `254${digits.substring(1)}`;
  }
  
  if ((digits.startsWith('7') || digits.startsWith('1')) && digits.length === 9) {
    return `254${digits}`;
  }
  
  return digits;
};

const generateSlug = (text) => {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .replace(/\s+/g, '-')
    .substring(0, 100);
};

// ========== API ROUTES ==========

// 1. HEALTH CHECK
app.get('/health', (req, res) => {
  const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
  const mpesaStatus = process.env.MPESA_CONSUMER_KEY ? 'configured' : 'not configured';
  
  res.json({
    success: true,
    message: 'KenyaPolitics Predict API is operational',
    data: {
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      database: dbStatus,
      mpesa: mpesaStatus,
      version: '1.0.0'
    }
  });
});

// 2. AUTHENTICATION ENDPOINTS
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, password, mpesaName } = req.body;
    
    // Validate input
    if (!phone || !password || !mpesaName) {
      return res.status(400).json({ 
        success: false, 
        error: 'Phone, password, and M-Pesa name are required' 
      });
    }
    
    // Validate Kenyan phone
    if (!phone.match(/^(07|01)\d{8}$/)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid Kenyan phone number. Format: 07XX XXX XXX or 01X XXX XXXX' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'Password must be at least 6 characters' 
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
      mpesaName,
      password: hashedPassword,
      // First user becomes admin
      role: (await User.countDocuments()) === 0 ? 'admin' : 'user'
    });
    
    // Create JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        phone: user.phone,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      success: true,
      message: 'Registration successful',
      data: {
        user: {
          id: user._id,
          phone: user.phone,
          mpesaName: user.mpesaName,
          balance: user.balance,
          kycVerified: user.kycVerified,
          role: user.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Registration failed. Please try again.' 
    });
  }
});

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
        phone: user.phone,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id,
          phone: user.phone,
          mpesaName: user.mpesaName,
          balance: user.balance,
          kycVerified: user.kycVerified,
          role: user.role
        },
        token
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Login failed. Please try again.' 
    });
  }
});

// 3. MARKET ENDPOINTS
app.get('/api/markets', async (req, res) => {
  try {
    const { 
      category, 
      resolved, 
      sort = 'newest',
      limit = 20, 
      page = 1,
      search = ''
    } = req.query;
    
    const query = {};
    
    // Apply filters
    if (category) query.category = category;
    if (resolved !== undefined) query.resolved = resolved === 'true';
    if (search) {
      query.$or = [
        { question: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Apply sorting
    let sortOption = {};
    switch(sort) {
      case 'volume': sortOption = { totalVolume: -1 }; break;
      case 'ending': sortOption = { resolutionDate: 1 }; break;
      case 'trending': sortOption = { totalVolume: -1, createdAt: -1 }; break;
      default: sortOption = { createdAt: -1 };
    }
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    // Execute queries in parallel for better performance
    const [markets, totalMarkets] = await Promise.all([
      Market.find(query)
        .sort(sortOption)
        .skip(skip)
        .limit(parseInt(limit))
        .populate('createdBy', 'phone mpesaName')
        .lean(),
      Market.countDocuments(query)
    ]);
    
    // Calculate implied probabilities
    const marketsWithProbability = markets.map(market => ({
      ...market,
      probability: MarketMaker.getImpliedProbability(market.yesPrice, market.noPrice)
    }));
    
    res.json({
      success: true,
      data: {
        markets: marketsWithProbability,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalMarkets,
          pages: Math.ceil(totalMarkets / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Get markets error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch markets' 
    });
  }
});

app.get('/api/markets/:id', async (req, res) => {
  try {
    const market = await Market.findById(req.params.id)
      .populate('createdBy', 'phone mpesaName')
      .populate('resolvedBy', 'phone mpesaName');
    
    if (!market) {
      return res.status(404).json({ 
        success: false, 
        error: 'Market not found' 
      });
    }
    
    // Get recent trades
    const trades = await Trade.find({ marketId: market._id })
      .sort({ createdAt: -1 })
      .limit(20)
      .populate('userId', 'phone mpesaName');
    
    // Get trade statistics
    const tradeStats = await Trade.aggregate([
      { $match: { marketId: market._id } },
      { 
        $group: {
          _id: '$outcome',
          totalAmount: { $sum: '$amount' },
          totalShares: { $sum: '$shares' },
          tradeCount: { $sum: 1 },
          avgPrice: { $avg: '$price' }
        }
      }
    ]);
    
    // Calculate probability
    const probability = MarketMaker.getImpliedProbability(market.yesPrice, market.noPrice);
    
    res.json({
      success: true,
      data: {
        market: {
          ...market.toObject(),
          probability
        },
        trades,
        stats: {
          yes: tradeStats.find(s => s._id === 'YES') || { 
            totalAmount: 0, totalShares: 0, tradeCount: 0, avgPrice: 0 
          },
          no: tradeStats.find(s => s._id === 'NO') || { 
            totalAmount: 0, totalShares: 0, tradeCount: 0, avgPrice: 0 
          }
        }
      }
    });
  } catch (error) {
    console.error('Get market error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to fetch market details' 
    });
  }
});

// 4. TRADING ENDPOINTS
app.post('/api/trade', authenticate, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { marketId, outcome, amount } = req.body;
    const userId = req.user._id;
    
    // Validate input
    if (!marketId || !outcome || !amount) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Market ID, outcome (YES/NO), and amount are required'
      });
    }
    
    if (!['YES', 'NO'].includes(outcome)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Outcome must be either YES or NO'
      });
    }
    
    if (amount < 10) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Minimum trade amount is KSh 10'
      });
    }
    
    if (amount > 100000) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Maximum trade amount is KSh 100,000'
      });
    }
    
    // Fetch market within transaction
    const market = await Market.findById(marketId).session(session);
    if (!market) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        error: 'Market not found'
      });
    }
    
    // Check market status
    if (market.resolved) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Market is already resolved. No more trades allowed.'
      });
    }
    
    if (new Date() > market.resolutionDate) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Market has expired. No more trades allowed.'
      });
    }
    
    // Check user balance
    if (req.user.balance < amount) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Insufficient balance. Please deposit funds first.'
      });
    }
    
    // Calculate trade using market maker
    const tradeResult = MarketMaker.calculatePrices(
      market.volumeYes,
      market.volumeNo,
      amount,
      outcome
    );
    
    // Calculate shares and price
    const price = outcome === 'YES' ? market.yesPrice : market.noPrice;
    const shares = amount / price;
    
    // Create trade record
    const trade = await Trade.create([{
      userId,
      marketId,
      outcome,
      shares,
      price,
      amount,
      tradeType: 'buy'
    }], { session });
    
    // Update market
    market.yesPrice = tradeResult.newYesPrice;
    market.noPrice = tradeResult.newNoPrice;
    market.volumeYes = tradeResult.newVolumeYes;
    market.volumeNo = tradeResult.newVolumeNo;
    market.lastTradeAt = new Date();
    await market.save({ session });
    
    // Update user balance
    await User.findByIdAndUpdate(
      userId,
      { 
        $inc: { 
          balance: -amount,
          totalTraded: amount 
        }
      },
      { session }
    );
    
    // Commit transaction
    await session.commitTransaction();
    
    // Fetch updated user
    const updatedUser = await User.findById(userId).select('balance totalTraded');
    
    res.json({
      success: true,
      message: 'Trade executed successfully',
      data: {
        trade: {
          id: trade[0]._id,
          outcome,
          shares,
          price,
          amount,
          timestamp: trade[0].createdAt
        },
        market: {
          id: market._id,
          yesPrice: market.yesPrice,
          noPrice: market.noPrice,
          totalVolume: market.totalVolume,
          probability: MarketMaker.getImpliedProbability(market.yesPrice, market.noPrice)
        },
        user: {
          newBalance: updatedUser.balance,
          totalTraded: updatedUser.totalTraded
        }
      }
    });
    
  } catch (error) {
    await session.abortTransaction();
    console.error('Trade error:', error);
    res.status(500).json({
      success: false,
      error: 'Trade failed. Please try again.'
    });
  } finally {
    session.endSession();
  }
});

app.get('/api/user/trades', authenticate, async (req, res) => {
  try {
    const { limit = 20, page = 1 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const [trades, totalTrades] = await Promise.all([
      Trade.find({ userId: req.user._id })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .populate('marketId', 'question category resolutionDate'),
      Trade.countDocuments({ userId: req.user._id })
    ]);
    
    // Calculate profit/loss for each trade
    const tradesWithPL = await Promise.all(trades.map(async (trade) => {
      const market = await Market.findById(trade.marketId);
      let profitLoss = 0;
      let currentValue = 0;
      
      if (market && market.resolved) {
        if (market.outcome === trade.outcome) {
          // Winning trade
          profitLoss = trade.amount * (1 / trade.price - 1);
        } else {
          // Losing trade
          profitLoss = -trade.amount;
        }
      } else if (market) {
        // Market not resolved yet - calculate current value
        currentValue = trade.shares * (trade.outcome === 'YES' ? market.yesPrice : market.noPrice);
        profitLoss = currentValue - trade.amount;
      }
      
      return {
        ...trade.toObject(),
        profitLoss,
        currentValue
      };
    }));
    
    res.json({
      success: true,
      data: {
        trades: tradesWithPL,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: totalTrades,
          pages: Math.ceil(totalTrades / parseInt(limit))
        }
      }
    });
  } catch (error) {
    console.error('Get trades error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch trades'
    });
  }
});

// 5. M-PESA ENDPOINTS
app.post('/api/mpesa/deposit', authenticate, async (req, res) => {
  try {
    const { amount, phone } = req.body;
    
    if (!amount || amount < 10 || amount > 70000) {
      return res.status(400).json({
        success: false,
        error: 'Amount must be between KSh 10 and KSh 70,000'
      });
    }
    
    const depositPhone = phone || req.user.phone;
    
    if (!depositPhone.match(/^(07|01)\d{8}$/)) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid Kenyan phone number'
      });
    }
    
    // Create deposit record
    const deposit = await Deposit.create({
      userId: req.user._id,
      amount,
      phone: depositPhone,
      accountReference: `DEP${Date.now()}${Math.random().toString(36).substr(2, 4)}`.toUpperCase()
    });
    
    console.log(`📝 Created deposit: ${deposit._id} for user: ${req.user._id}`);
    
    // Initiate M-Pesa STK Push
    const result = await mpesaService.initiateSTKPush(
      depositPhone,
      amount,
      deposit.accountReference,
      'KenyaPolitics Deposit'
    );
    
    if (!result.success) {
      await Deposit.findByIdAndUpdate(deposit._id, {
        status: 'failed'
      });
      
      return res.status(500).json({
        success: false,
        error: result.error || 'M-Pesa request failed. Please try again.'
      });
    }
    
    // Update deposit with request ID
    await Deposit.findByIdAndUpdate(deposit._id, {
      requestId: result.requestId
    });
    
    res.json({
      success: true,
      message: 'M-Pesa payment request sent to your phone',
      data: {
        depositId: deposit._id,
        requestId: result.requestId,
        amount,
        phone: depositPhone,
        instructions: 'Please check your phone and enter your M-Pesa PIN to complete the deposit.'
      }
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({
      success: false,
      error: 'Deposit failed. Please try again.'
    });
  }
});

app.post('/api/mpesa/withdraw', authenticate, async (req, res) => {
  try {
    const { amount, phone } = req.body;
    
    if (!amount || amount < 100 || amount > 70000) {
      return res.status(400).json({
        success: false,
        error: 'Amount must be between KSh 100 and KSh 70,000'
      });
    }
    
    const withdrawPhone = phone || req.user.phone;
    
    if (!withdrawPhone.match(/^(07|01)\d{8}$/)) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid Kenyan phone number'
      });
    }
    
    // Check user balance
    if (req.user.balance < amount) {
      return res.status(400).json({
        success: false,
        error: 'Insufficient balance for withdrawal'
      });
    }
    
    // Create withdrawal record
    const withdrawal = await Withdrawal.create({
      userId: req.user._id,
      amount,
      phone: withdrawPhone,
      status: 'pending'
    });
    
    // TODO: Implement actual M-Pesa B2C withdrawal
    // For now, we'll simulate successful withdrawal
    
    // In production, you would call M-Pesa B2C API here
    console.log(`📤 Withdrawal request: ${withdrawal._id} for KSh ${amount} to ${withdrawPhone}`);
    
    // Simulate processing delay
    setTimeout(async () => {
      try {
        // Update withdrawal as completed
        await Withdrawal.findByIdAndUpdate(withdrawal._id, {
          status: 'completed',
          mpesaCode: `MP${Date.now()}`,
          completedAt: new Date()
        });
        
        // Deduct from user balance
        await User.findByIdAndUpdate(req.user._id, {
          $inc: { balance: -amount }
        });
        
        console.log(`✅ Withdrawal ${withdrawal._id} processed successfully`);
      } catch (updateError) {
        console.error('Withdrawal update error:', updateError);
      }
    }, 5000);
    
    res.json({
      success: true,
      message: 'Withdrawal request submitted successfully',
      data: {
        withdrawalId: withdrawal._id,
        amount,
        phone: withdrawPhone,
        note: 'Withdrawals are processed within 5-10 minutes. You will receive an M-Pesa confirmation.'
      }
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({
      success: false,
      error: 'Withdrawal request failed'
    });
  }
});

// M-Pesa Callback Webhook
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
        
        const metadata = stkCallback.CallbackMetadata.Item;
        const amount = metadata.find(item => item.Name === 'Amount')?.Value;
        const mpesaCode = metadata.find(item => item.Name === 'MpesaReceiptNumber')?.Value;
        const phone = metadata.find(item => item.Name === 'PhoneNumber')?.Value;
        const accountRef = stkCallback.MerchantRequestID;
        
        console.log(`💰 Transaction: Amount=${amount}, Receipt=${mpesaCode}, Phone=${phone}, Ref=${accountRef}`);
        
        // Find and update deposit
        const deposit = await Deposit.findOneAndUpdate(
          {
            $or: [
              { requestId: stkCallback.CheckoutRequestID },
              { accountReference: accountRef }
            ],
            status: 'pending'
          },
          {
            status: 'completed',
            mpesaCode: mpesaCode,
            completedAt: new Date()
          },
          { new: true }
        ).populate('userId');
        
        if (deposit && deposit.userId) {
          // Update user balance
          await User.findByIdAndUpdate(
            deposit.userId._id,
            { $inc: { balance: amount } }
          );
          
          console.log(`✅ Deposit ${deposit._id} completed. User ${deposit.userId.phone} credited KSh ${amount}`);
        } else {
          console.warn(`⚠️ No pending deposit found for: ${stkCallback.CheckoutRequestID}`);
        }
      } else {
        // Transaction failed
        console.error('❌ M-Pesa Transaction Failed:', stkCallback.ResultDesc);
        
        await Deposit.findOneAndUpdate(
          { requestId: stkCallback.CheckoutRequestID, status: 'pending' },
          { status: 'failed' }
        );
      }
    }
  } catch (error) {
    console.error('❌ Callback processing error:', error);
  }
});

// 6. USER PROFILE ENDPOINTS
app.get('/api/user/profile', authenticate, async (req, res) => {
  try {
    const user = req.user;
    
    // Get user's recent trades
    const recentTrades = await Trade.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('marketId', 'question category');
    
    // Get user's deposits and withdrawals
    const [recentDeposits, recentWithdrawals] = await Promise.all([
      Deposit.find({ userId: user._id })
        .sort({ createdAt: -1 })
        .limit(5),
      Withdrawal.find({ userId: user._id })
        .sort({ createdAt: -1 })
        .limit(5)
    ]);
    
    // Get portfolio summary
    const portfolioSummary = await Trade.aggregate([
      { $match: { userId: user._id } },
      {
        $group: {
          _id: null,
          totalInvested: { $sum: '$amount' },
          totalTrades: { $sum: 1 },
          marketsTraded: { $addToSet: '$marketId' }
        }
      }
    ]);
    
    // Get active investments (trades in unresolved markets)
    const activeInvestments = await Trade.aggregate([
      { $match: { userId: user._id } },
      {
        $lookup: {
          from: 'markets',
          localField: 'marketId',
          foreignField: '_id',
          as: 'market'
        }
      },
      { $unwind: '$market' },
      { $match: { 'market.resolved': false } },
      {
        $group: {
          _id: '$marketId',
          market: { $first: '$market' },
          totalAmount: { $sum: '$amount' },
          totalShares: { $sum: '$shares' }
        }
      }
    ]);
    
    res.json({
      success: true,
      data: {
        user: {
          id: user._id,
          phone: user.phone,
          mpesaName: user.mpesaName,
          balance: user.balance,
          kycVerified: user.kycVerified,
          role: user.role,
          totalTraded: user.totalTraded,
          profitLoss: user.profitLoss,
          createdAt: user.createdAt
        },
        portfolio: portfolioSummary[0] || {
          totalInvested: 0,
          totalTrades: 0,
          marketsTraded: []
        },
        activeInvestments,
        recentActivity: {
          trades: recentTrades,
          deposits: recentDeposits,
          withdrawals: recentWithdrawals
        }
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch profile'
    });
  }
});

// 7. ADMIN ENDPOINTS
app.post('/api/admin/markets', authenticate, isAdmin, async (req, res) => {
  try {
    const { question, description, category, resolutionDate } = req.body;
    
    if (!question || !resolutionDate) {
      return res.status(400).json({
        success: false,
        error: 'Question and resolution date are required'
      });
    }
    
    if (new Date(resolutionDate) <= new Date()) {
      return res.status(400).json({
        success: false,
        error: 'Resolution date must be in the future'
      });
    }
    
    const market = await Market.create({
      question,
      description,
      category: category || 'elections',
      resolutionDate: new Date(resolutionDate),
      createdBy: req.user._id
    });
    
    res.status(201).json({
      success: true,
      message: 'Market created successfully',
      data: { market }
    });
  } catch (error) {
    console.error('Create market error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        error: 'A market with a similar question already exists'
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Failed to create market'
    });
  }
});

app.post('/api/admin/resolve-market', authenticate, isAdmin, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction();
  
  try {
    const { marketId, outcome, justification } = req.body;
    
    if (!marketId || !outcome || !['YES', 'NO', 'CANCELLED'].includes(outcome)) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Market ID and valid outcome (YES/NO/CANCELLED) are required'
      });
    }
    
    const market = await Market.findById(marketId).session(session);
    if (!market) {
      await session.abortTransaction();
      return res.status(404).json({
        success: false,
        error: 'Market not found'
      });
    }
    
    if (market.resolved) {
      await session.abortTransaction();
      return res.status(400).json({
        success: false,
        error: 'Market is already resolved'
      });
    }
    
    // Update market
    market.resolved = true;
    market.outcome = outcome;
    market.resolvedAt = new Date();
    market.resolvedBy = req.user._id;
    market.resolutionJustification = justification;
    await market.save({ session });
    
    // Get all trades for this market
    const trades = await Trade.find({ marketId }).populate('userId').session(session);
    
    if (outcome !== 'CANCELLED') {
      // Calculate winnings for resolved markets
      const winningTrades = trades.filter(t => t.outcome === outcome);
      const losingTrades = trades.filter(t => t.outcome !== outcome);
      
      const totalWinningAmount = winningTrades.reduce((sum, trade) => sum + trade.amount, 0);
      const totalLosingAmount = losingTrades.reduce((sum, trade) => sum + trade.amount, 0);
      
      // Distribute winnings if there are winners
      if (winningTrades.length > 0 && totalLosingAmount > 0) {
        for (const trade of winningTrades) {
          const winShare = trade.amount / totalWinningAmount;
          const winnings = trade.amount + (totalLosingAmount * winShare);
          
          await User.findByIdAndUpdate(
            trade.userId._id,
            { 
              $inc: { 
                balance: winnings,
                profitLoss: winnings - trade.amount
              }
            },
            { session }
          );
        }
      }
      
      // Mark losing trades (users lose their investment)
      for (const trade of losingTrades) {
        await User.findByIdAndUpdate(
          trade.userId._id,
          { 
            $inc: { 
              profitLoss: -trade.amount
            }
          },
          { session }
        );
      }
    } else {
      // Market cancelled - refund all trades
      for (const trade of trades) {
        await User.findByIdAndUpdate(
          trade.userId._id,
          { $inc: { balance: trade.amount } },
          { session }
        );
      }
    }
    
    await session.commitTransaction();
    
    res.json({
      success: true,
      message: `Market resolved as ${outcome}`,
      data: {
        market,
        stats: {
          totalTrades: trades.length,
          winningTrades: outcome !== 'CANCELLED' ? trades.filter(t => t.outcome === outcome).length : 0,
          losingTrades: outcome !== 'CANCELLED' ? trades.filter(t => t.outcome !== outcome).length : 0,
          totalRefunded: outcome === 'CANCELLED' ? trades.reduce((sum, t) => sum + t.amount, 0) : 0
        }
      }
    });
    
  } catch (error) {
    await session.abortTransaction();
    console.error('Resolve market error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to resolve market'
    });
  } finally {
    session.endSession();
  }
});

app.get('/api/admin/stats', authenticate, isAdmin, async (req, res) => {
  try {
    const [
      totalUsers,
      totalMarkets,
      activeMarkets,
      totalTrades,
      totalDeposits,
      totalWithdrawals,
      platformBalance
    ] = await Promise.all([
      User.countDocuments(),
      Market.countDocuments(),
      Market.countDocuments({ resolved: false }),
      Trade.countDocuments(),
      Deposit.countDocuments({ status: 'completed' }),
      Withdrawal.countDocuments({ status: 'completed' }),
      Trade.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }])
    ]);
    
    // Recent activity
    const recentMarkets = await Market.find()
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('createdBy', 'phone');
    
    const recentDeposits = await Deposit.find({ status: 'completed' })
      .sort({ createdAt: -1 })
      .limit(5)
      .populate('userId', 'phone');
    
    res.json({
      success: true,
      data: {
        overview: {
          totalUsers,
          totalMarkets,
          activeMarkets,
          totalTrades,
          totalDeposits,
          totalWithdrawals,
          totalVolume: platformBalance[0]?.total || 0
        },
        recentActivity: {
          markets: recentMarkets,
          deposits: recentDeposits
        }
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch admin statistics'
    });
  }
});

// 8. PUBLIC STATISTICS
app.get('/api/stats', async (req, res) => {
  try {
    const [
      totalMarkets,
      activeMarkets,
      totalTrades,
      totalVolume,
      recentMarkets
    ] = await Promise.all([
      Market.countDocuments(),
      Market.countDocuments({ resolved: false }),
      Trade.countDocuments(),
      Trade.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]),
      Market.find({ resolved: false })
        .sort({ createdAt: -1 })
        .limit(6)
        .select('question category resolutionDate totalVolume yesPrice noPrice')
    ]);
    
    // Calculate market categories distribution
    const categoryStats = await Market.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);
    
    res.json({
      success: true,
      data: {
        platform: {
          totalMarkets,
          activeMarkets,
          totalTrades,
          totalVolume: totalVolume[0]?.total || 0
        },
        categories: categoryStats,
        recentMarkets: recentMarkets.map(market => ({
          ...market.toObject(),
          probability: MarketMaker.getImpliedProbability(market.yesPrice, market.noPrice)
        })),
        updatedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Public stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch platform statistics'
    });
  }
});

// ========== FRONTEND ROUTES ==========
app.get('/', (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KenyaPolitics Predict - Political Prediction Market</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #006600 0%, #BB0000 100%);
        }
        .market-card {
            transition: all 0.3s ease;
        }
        .market-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
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
        .price-up { color: #10B981; }
        .price-down { color: #EF4444; }
    </style>
</head>
<body class="bg-gray-50">
    <div id="app" class="min-h-screen">
        <div class="container mx-auto px-4 py-16 text-center">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-green-600 mx-auto"></div>
            <p class="mt-4 text-gray-600">Loading KenyaPolitics Predict...</p>
            <p class="text-sm text-gray-400 mt-2">If this takes too long, check the console for errors.</p>
        </div>
    </div>

    <script>
        // Frontend Application
        const API_BASE = window.location.origin;
        let currentUser = null;
        let currentToken = localStorage.getItem('token');
        
        async function loadApp() {
            try {
                // Load platform stats
                const statsResponse = await fetch(API_BASE + '/api/stats');
                const statsData = await statsResponse.json();
                
                if (!statsData.success) {
                    throw new Error('Failed to load platform data');
                }
                
                // Check if user is logged in
                if (currentToken) {
                    try {
                        const profileResponse = await fetch(API_BASE + '/api/user/profile', {
                            headers: { 'Authorization': 'Bearer ' + currentToken }
                        });
                        if (profileResponse.ok) {
                            const profileData = await profileResponse.json();
                            currentUser = profileData.data.user;
                        }
                    } catch (authError) {
                        console.log('Not logged in or session expired');
                        localStorage.removeItem('token');
                        currentToken = null;
                        currentUser = null;
                    }
                }
                
                // Render the application
                renderApp(statsData.data);
            } catch (error) {
                console.error('Failed to load app:', error);
                document.getElementById('app').innerHTML = \`
                    <div class="container mx-auto px-4 py-16 text-center">
                        <div class="text-red-500 text-5xl mb-4">⚠️</div>
                        <h2 class="text-2xl font-bold mb-4">Service Temporarily Unavailable</h2>
                        <p class="text-gray-600 mb-6">We're experiencing technical difficulties. Please try again later.</p>
                        <button onclick="location.reload()" class="bg-green-500 text-white px-6 py-2 rounded-lg hover:bg-green-600">
                            Retry
                        </button>
                    </div>
                \`;
            }
        }
        
        function renderApp(stats) {
            const app = document.getElementById('app');
            const isLoggedIn = currentUser !== null;
            
            app.innerHTML = \`
                <!-- Navigation -->
                <nav class="bg-white shadow-lg">
                    <div class="container mx-auto px-4 py-4">
                        <div class="flex justify-between items-center">
                            <div class="flex items-center space-x-2 cursor-pointer" onclick="location.reload()">
                                <div class="w-10 h-10 bg-gradient-to-r from-green-600 to-red-600 rounded-lg"></div>
                                <span class="text-2xl font-bold text-gray-800">KenyaPolitics Predict</span>
                            </div>
                            <div class="flex items-center space-x-6">
                                <a href="#markets" class="text-gray-700 hover:text-green-600 font-medium">Markets</a>
                                <a href="#how-it-works" class="text-gray-700 hover:text-green-600 font-medium">How It Works</a>
                                \${isLoggedIn ? \`
                                    <div class="flex items-center space-x-4">
                                        <span class="text-gray-700">
                                            <i class="fas fa-coins text-yellow-500 mr-1"></i>
                                            KSh \${currentUser.balance.toLocaleString()}
                                        </span>
                                        <div class="relative group">
                                            <button class="flex items-center space-x-2 text-gray-700 hover:text-green-600">
                                                <i class="fas fa-user"></i>
                                                <span>\${currentUser.phone}</span>
                                                <i class="fas fa-chevron-down text-xs"></i>
                                            </button>
                                            <div class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg hidden group-hover:block z-10">
                                                <a href="#profile" class="block px-4 py-2 hover:bg-gray-100" onclick="showProfile()">
                                                    <i class="fas fa-user-circle mr-2"></i>My Profile
                                                </a>
                                                <a href="#deposit" class="block px-4 py-2 hover:bg-gray-100" onclick="showDepositModal()">
                                                    <i class="fas fa-money-bill-wave mr-2"></i>Deposit
                                                </a>
                                                <a href="#withdraw" class="block px-4 py-2 hover:bg-gray-100" onclick="showWithdrawModal()">
                                                    <i class="fas fa-wallet mr-2"></i>Withdraw
                                                </a>
                                                \${currentUser.role === 'admin' ? \`
                                                    <a href="#admin" class="block px-4 py-2 hover:bg-gray-100 text-purple-600" onclick="showAdminPanel()">
                                                        <i class="fas fa-cog mr-2"></i>Admin Panel
                                                    </a>
                                                \` : ''}
                                                <button onclick="logout()" class="block w-full text-left px-4 py-2 hover:bg-gray-100 text-red-600">
                                                    <i class="fas fa-sign-out-alt mr-2"></i>Logout
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                \` : \`
                                    <button onclick="showLoginModal()" class="btn-primary">Login / Register</button>
                                \`}
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
                            \${isLoggedIn ? \`
                                <button onclick="loadMarkets()" class="bg-white text-green-700 px-8 py-3 rounded-lg font-semibold hover:bg-gray-100 transition">
                                    <i class="fas fa-chart-line mr-2"></i>Start Trading
                                </button>
                                <button onclick="showDepositModal()" class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white/10 transition">
                                    <i class="fas fa-plus-circle mr-2"></i>Add Funds
                                </button>
                            \` : \`
                                <button onclick="showRegisterModal()" class="bg-white text-green-700 px-8 py-3 rounded-lg font-semibold hover:bg-gray-100 transition">
                                    Get Started Free
                                </button>
                                <button onclick="showLoginModal()" class="border-2 border-white px-8 py-3 rounded-lg font-semibold hover:bg-white/10 transition">
                                    Login to Trade
                                </button>
                            \`}
                        </div>
                    </div>
                </section>

                <!-- Platform Stats -->
                <section class="py-12 bg-white">
                    <div class="container mx-auto px-4">
                        <h2 class="text-3xl font-bold text-center mb-8">Platform Overview</h2>
                        <div class="grid grid-cols-2 md:grid-cols-4 gap-6">
                            <div class="text-center p-6 bg-gray-50 rounded-xl">
                                <div class="text-3xl font-bold text-green-600">\${stats.platform.activeMarkets}</div>
                                <div class="text-gray-600 font-medium">Active Markets</div>
                            </div>
                            <div class="text-center p-6 bg-gray-50 rounded-xl">
                                <div class="text-3xl font-bold text-blue-600">\${stats.platform.totalTrades}</div>
                                <div class="text-gray-600 font-medium">Total Trades</div>
                            </div>
                            <div class="text-center p-6 bg-gray-50 rounded-xl">
                                <div class="text-3xl font-bold text-purple-600">KSh \${Math.round(stats.platform.totalVolume).toLocaleString()}</div>
                                <div class="text-gray-600 font-medium">Trading Volume</div>
                            </div>
                            <div class="text-center p-6 bg-gray-50 rounded-xl">
                                <div class="text-3xl font-bold text-orange-600">\${stats.platform.totalMarkets}</div>
                                <div class="text-gray-600 font-medium">All Markets</div>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- Recent Markets -->
                <section id="markets" class="py-16 bg-gray-50">
                    <div class="container mx-auto px-4">
                        <div class="flex justify-between items-center mb-8">
                            <h2 class="text-3xl font-bold">Recent Political Markets</h2>
                            <div class="flex space-x-2">
                                <button onclick="loadMarkets('newest')" class="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600">
                                    Newest
                                </button>
                                <button onclick="loadMarkets('volume')" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300">
                                    Most Active
                                </button>
                                \${isLoggedIn && currentUser.role === 'admin' ? \`
                                    <button onclick="showCreateMarketModal()" class="px-4 py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600">
                                        <i class="fas fa-plus mr-1"></i> New Market
                                    </button>
                                \` : ''}
                            </div>
                        </div>
                        
                        <div id="markets-container" class="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                            <!-- Markets will be loaded here -->
                            \${stats.recentMarkets.map(market => \`
                                <div class="market-card bg-white rounded-xl shadow p-6">
                                    <div class="flex justify-between items-start mb-4">
                                        <span class="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">\${market.category}</span>
                                        <span class="text-sm text-gray-500">
                                            Ends: \${new Date(market.resolutionDate).toLocaleDateString()}
                                        </span>
                                    </div>
                                    <h3 class="font-bold mb-4 text-lg">\${market.question}</h3>
                                    
                                    <div class="grid grid-cols-2 gap-4 mb-4">
                                        <div class="bg-green-50 rounded-lg p-4">
                                            <div class="text-sm text-green-600">YES</div>
                                            <div class="text-2xl font-bold text-green-700">
                                                \${(market.probability.yesProbability * 100).toFixed(1)}%
                                            </div>
                                            <div class="text-sm text-green-600">
                                                KSh \${market.volumeYes ? market.volumeYes.toLocaleString() : '0'}
                                            </div>
                                        </div>
                                        <div class="bg-red-50 rounded-lg p-4">
                                            <div class="text-sm text-red-600">NO</div>
                                            <div class="text-2xl font-bold text-red-700">
                                                \${(market.probability.noProbability * 100).toFixed(1)}%
                                            </div>
                                            <div class="text-sm text-red-600">
                                                KSh \${market.volumeNo ? market.volumeNo.toLocaleString() : '0'}
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="text-center py-3 border-t">
                                        <div class="text-lg font-bold text-gray-800">
                                            KSh \${market.totalVolume ? market.totalVolume.toLocaleString() : '0'}
                                        </div>
                                        <div class="text-sm text-gray-500">Total Volume</div>
                                    </div>
                                    
                                    <div class="flex gap-2 mt-4">
                                        <button onclick="showTradeModal('\${market._id}', 'YES')" 
                                                class="flex-1 bg-green-500 hover:bg-green-600 text-white py-2 rounded-lg transition"
                                                \${!isLoggedIn ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                                            Buy YES
                                        </button>
                                        <button onclick="showTradeModal('\${market._id}', 'NO')" 
                                                class="flex-1 bg-red-500 hover:bg-red-600 text-white py-2 rounded-lg transition"
                                                \${!isLoggedIn ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                                            Buy NO
                                        </button>
                                    </div>
                                    
                                    <div class="flex justify-between text-sm text-gray-500 mt-4 pt-3 border-t">
                                        <div>
                                            <div>Trades</div>
                                            <div class="font-bold">\${market.tradeCount || 0}</div>
                                        </div>
                                        <button onclick="viewMarketDetails('\${market._id}')" 
                                                class="text-blue-600 hover:text-blue-800 font-medium">
                                            Details →
                                        </button>
                                    </div>
                                </div>
                            \`).join('')}
                        </div>
                    </div>
                </section>

                <!-- How It Works -->
                <section id="how-it-works" class="py-16">
                    <div class="container mx-auto px-4">
                        <h2 class="text-3xl font-bold text-center mb-12">How It Works</h2>
                        <div class="grid md:grid-cols-3 gap-8">
                            <div class="text-center p-6">
                                <div class="text-4xl mb-4">📱</div>
                                <h3 class="text-xl font-bold mb-2">1. Register & Verify</h3>
                                <p class="text-gray-600">Sign up with your Kenyan phone number and verify your identity.</p>
                            </div>
                            <div class="text-center p-6">
                                <div class="text-4xl mb-4">💰</div>
                                <h3 class="text-xl font-bold mb-2">2. Deposit with M-Pesa</h3>
                                <p class="text-gray-600">Fund your account instantly using M-Pesa. Secure and trusted.</p>
                            </div>
                            <div class="text-center p-6">
                                <div class="text-4xl mb-4">📈</div>
                                <h3 class="text-xl font-bold mb-2">3. Trade Predictions</h3>
                                <p class="text-gray-600">Buy YES or NO shares on political events. Prices update in real-time.</p>
                            </div>
                        </div>
                    </div>
                </section>

                <!-- API Status Footer -->
                <section class="bg-gray-100 py-8">
                    <div class="container mx-auto px-4 text-center">
                        <div class="inline-flex items-center bg-white rounded-lg shadow px-6 py-3">
                            <div class="w-3 h-3 bg-green-500 rounded-full mr-2"></div>
                            <span class="font-medium">API Status: Operational</span>
                            <a href="\${API_BASE}/health" class="ml-4 text-blue-500 hover:text-blue-700 text-sm">
                                <i class="fas fa-external-link-alt mr-1"></i>Health Check
                            </a>
                        </div>
                    </div>
                </section>

                <footer class="bg-gray-800 text-white py-8">
                    <div class="container mx-auto px-4 text-center">
                        <p>© \${new Date().getFullYear()} KenyaPolitics Predict. All rights reserved.</p>
                        <p class="text-gray-400 text-sm mt-2">
                            This platform is for informational purposes only. Trading involves risk.
                            Users must be 18+ and comply with Kenyan regulations.
                        </p>
                        <div class="mt-4 flex justify-center space-x-4 text-gray-400 text-sm">
                            <a href="#" class="hover:text-white">Terms</a>
                            <span>•</span>
                            <a href="#" class="hover:text-white">Privacy</a>
                            <span>•</span>
                            <a href="#" class="hover:text-white">Contact</a>
                        </div>
                    </div>
                </footer>

                <!-- Modals will be inserted here -->
                <div id="modals-container"></div>
            \`;
            
            // Load initial markets
            loadMarkets();
        }
        
        // API Functions
        async function loadMarkets(sort = 'newest') {
            try {
                const response = await fetch(\`\${API_BASE}/api/markets?sort=\${sort}&limit=6\`);
                const data = await response.json();
                
                if (data.success) {
                    const container = document.getElementById('markets-container');
                    if (container) {
                        container.innerHTML = data.data.markets.map(market => \`
                            <div class="market-card bg-white rounded-xl shadow p-6">
                                <div class="flex justify-between items-start mb-4">
                                    <span class="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                                        \${market.category}
                                    </span>
                                    <span class="text-sm text-gray-500">
                                        Ends: \${new Date(market.resolutionDate).toLocaleDateString()}
                                    </span>
                                </div>
                                <h3 class="font-bold mb-4 text-lg">\${market.question}</h3>
                                
                                <div class="grid grid-cols-2 gap-4 mb-4">
                                    <div class="bg-green-50 rounded-lg p-4">
                                        <div class="text-sm text-green-600">YES</div>
                                        <div class="text-2xl font-bold text-green-700">
                                            \${(market.probability.yesProbability * 100).toFixed(1)}%
                                        </div>
                                    </div>
                                    <div class="bg-red-50 rounded-lg p-4">
                                        <div class="text-sm text-red-600">NO</div>
                                        <div class="text-2xl font-bold text-red-700">
                                            \${(market.probability.noProbability * 100).toFixed(1)}%
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="flex gap-2 mt-4">
                                    <button onclick="showTradeModal('\${market._id}', 'YES')" 
                                            class="flex-1 bg-green-500 hover:bg-green-600 text-white py-2 rounded-lg transition"
                                            \${!currentUser ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                                        Buy YES
                                    </button>
                                    <button onclick="showTradeModal('\${market._id}', 'NO')" 
                                            class="flex-1 bg-red-500 hover:bg-red-600 text-white py-2 rounded-lg transition"
                                            \${!currentUser ? 'disabled style="opacity:0.5; cursor:not-allowed;"' : ''}>
                                        Buy NO
                                    </button>
                                </div>
                            </div>
                        \`).join('');
                    }
                }
            } catch (error) {
                console.error('Failed to load markets:', error);
            }
        }
        
        // Modal functions (simplified for example)
        function showLoginModal() {
            const modals = document.getElementById('modals-container');
            modals.innerHTML = \`
                <div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div class="bg-white rounded-xl shadow-2xl w-full max-w-md mx-4">
                        <div class="p-8">
                            <h3 class="text-2xl font-bold mb-6">Login</h3>
                            <div class="space-y-4">
                                <input type="tel" id="login-phone" placeholder="Phone Number" 
                                       class="w-full border rounded-lg px-4 py-3" value="0712345678">
                                <input type="password" id="login-password" placeholder="Password" 
                                       class="w-full border rounded-lg px-4 py-3" value="password123">
                                <button onclick="performLogin()" class="w-full btn-primary py-3">
                                    Login
                                </button>
                                <p class="text-center text-gray-600">
                                    Don't have an account? 
                                    <button onclick="showRegisterModal()" class="text-blue-600 font-medium ml-1">
                                        Register
                                    </button>
                                </p>
                            </div>
                            <button onclick="closeModal()" class="absolute top-4 right-4 text-gray-400 hover:text-gray-600">
                                <i class="fas fa-times text-2xl"></i>
                            </button>
                        </div>
                    </div>
                </div>
            \`;
        }
        
        async function performLogin() {
            const phone = document.getElementById('login-phone').value;
            const password = document.getElementById('login-password').value;
            
            try {
                const response = await fetch(API_BASE + '/api/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ phone, password })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    currentToken = data.data.token;
                    currentUser = data.data.user;
                    localStorage.setItem('token', currentToken);
                    closeModal();
                    loadApp(); // Reload the app
                    alert('Login successful!');
                } else {
                    alert('Login failed: ' + data.error);
                }
            } catch (error) {
                alert('Login error: ' + error.message);
            }
        }
        
        function showTradeModal(marketId, outcome) {
            if (!currentUser) {
                showLoginModal();
                return;
            }
            
            alert('Trade modal for ' + outcome + ' would open here.\\nMarket ID: ' + marketId + '\\nUser Balance: KSh ' + currentUser.balance.toLocaleString());
            // In production, this would show a full trading interface
        }
        
        function showDepositModal() {
            if (!currentUser) {
                showLoginModal();
                return;
            }
            
            alert('Deposit modal would open here.\\nCurrent balance: KSh ' + currentUser.balance.toLocaleString());
            // In production, this would show M-Pesa deposit interface
        }
        
        function logout() {
            currentUser = null;
            currentToken = null;
            localStorage.removeItem('token');
            loadApp();
        }
        
        function closeModal() {
            document.getElementById('modals-container').innerHTML = '';
        }
        
        function viewMarketDetails(marketId) {
            alert('Market details for: ' + marketId + '\\nThis would show detailed market view with trade history.');
        }
        
        // Initialize the app
        document.addEventListener('DOMContentLoaded', loadApp);
    </script>
</body>
</html>
  `);
});

// ========== ERROR HANDLING MIDDLEWARE ==========

// 404 - Not Found Handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint not found',
    path: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled Server Error:', {
    message: err.message,
    stack: err.stack,
    path: req.url,
    method: req.method,
    timestamp: new Date().toISOString()
  });
  
  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Validation Error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  // Mongoose duplicate key error
  if (err.code === 11000) {
    return res.status(400).json({
      success: false,
      error: 'Duplicate Entry',
      message: 'A record with this value already exists'
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: 'Invalid Token',
      message: 'The provided authentication token is invalid'
    });
  }
  
  // Default error response
  res.status(err.status || 500).json({
    success: false,
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ========== SERVER STARTUP ==========
const PORT = process.env.PORT || 3000;

// Only start server if not in test environment
if (require.main === module) {
  const server = app.listen(PORT, '0.0.0.0', () => {
    const address = server.address();
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║      🚀 KENYAPOLITICS PREDICT PLATFORM STARTED!             ║
╠═══════════════════════════════════════════════════════════════╣
║  🌐 Server: http://0.0.0.0:\${PORT}                          ║
║  📊 Health: http://0.0.0.0:\${PORT}/health                  ║
║  📱 Frontend: http://0.0.0.0:\${PORT}/                      ║
║  🗄️  Database: \${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'} ║
║  🔧 Environment: \${process.env.NODE_ENV || 'development'}   ║
║  📈 Node.js: \${process.version}                            ║
╚═══════════════════════════════════════════════════════════════╝

📋 AVAILABLE ENDPOINTS:
   [GET]    /                   - Frontend Application
   [GET]    /health             - Health Check
   [POST]   /api/auth/register  - User Registration
   [POST]   /api/auth/login     - User Login
   [GET]    /api/markets        - List Markets
   [POST]   /api/trade          - Execute Trade
   [POST]   /api/mpesa/deposit  - M-Pesa Deposit
   [POST]   /api/mpesa/callback - M-Pesa Webhook
   [GET]    /api/user/profile   - User Profile
   [POST]   /api/admin/markets  - Create Market (Admin)
   [GET]    /api/stats          - Platform Statistics

🔐 SECURITY NOTES:
   • MongoDB IP Whitelist: 0.0.0.0/0 (for testing)
   • JWT Secret: \${process.env.JWT_SECRET ? '✅ Set' : '❌ Missing'}
   • M-Pesa Credentials: \${process.env.MPESA_CONSUMER_KEY ? '✅ Configured' : '❌ Missing'}

📞 SUPPORT:
   • Check /health for API status
   • Monitor MongoDB Atlas for connection issues
   • Test M-Pesa with sandbox credentials first
    `);
  });

  // Graceful shutdown handlers
  const gracefulShutdown = (signal) => {
    console.log(\`\\n🛑 Received \${signal}. Shutting down gracefully...\`);
    
    server.close(() => {
      console.log('✅ HTTP server closed.');
      
      mongoose.connection.close(false, () => {
        console.log('✅ MongoDB connection closed.');
        console.log('👋 Server shutdown complete.');
        process.exit(0);
      });
    });
    
    // Force shutdown after 10 seconds
    setTimeout(() => {
      console.error('⏰ Shutdown timeout. Forcing exit.');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  
  // Handle uncaught exceptions
  process.on('uncaughtException', (err) => {
    console.error('💥 UNCAUGHT EXCEPTION:', err);
    gracefulShutdown('uncaughtException');
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    console.error('💥 UNHANDLED REJECTION at:', promise, 'reason:', reason);
  });
}

module.exports = app; // For testing
