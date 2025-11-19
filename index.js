// =================================================================
//                      IMPORTS AND CONFIGURATION
// =================================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// =================================================================
//                           MIDDLEWARE
// =================================================================

// CRITICAL CORS FIX: Ensure all variations of your frontend URL are allowed.
const allowedOrigins = [
    'https://registration-dashboard-frontend.vercel.app', 
    'https://registration-dashboard-frontend.vercel.app/', 
    'http://localhost:3000' 
];
app.use(cors({
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));

app.use(express.json()); 

// =================================================================
//                        DATABASE CONNECTION
// =================================================================

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

let isConnected;

const connectDb = async () => {
    if (isConnected) {
        console.log('=> Using existing database connection');
        return;
    }

    if (!MONGO_URI) {
        throw new Error('MONGO_URI_MISSING'); 
    }
    
    try {
        await mongoose.connect(MONGO_URI);
        isConnected = true;
        console.log('=> New database connection established');
    } catch (err) {
        console.error('MongoDB connection error:', err.message);
        throw new Error('DATABASE_CONNECTION_FAILED');
    }
};

// =================================================================
//                         DATABASE SCHEMA & MODEL
// =================================================================

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// =================================================================
//                            API ROUTES
// =================================================================

/**
 * Wrapper with complete error handling for database connection failures.
 */
const routeHandler = (handler) => async (req, res) => {
    try {
        await connectDb();
        await handler(req, res);
    } catch (error) {
        console.error("Route Handler Error:", error.message);

        if (error.message === 'MONGO_URI_MISSING' || error.message === 'JWT_SECRET_MISSING') {
            return res.status(500).json({ 
                message: 'Server configuration error: Required environment variable is missing.' 
            });
        }
        
        if (error.message === 'DATABASE_CONNECTION_FAILED') {
            return res.status(503).json({ 
                message: 'Service temporarily unavailable. Check MongoDB IP Whitelisting.' 
            });
        }

        if (error.code === 11000) { 
            const field = Object.keys(error.keyPattern)[0];
            return res.status(409).json({
                message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.`
            });
        }

        res.status(500).json({ message: 'Internal Server Error.' });
    }
};


// ------------------------- REGISTRATION ROUTE -------------------------
app.post('/api/auth/register', routeHandler(async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields.' });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const field = existingUser.email.toLowerCase() === email.toLowerCase() ? 'Email' : 'Username';
      return res.status(409).json({ message: `${field} is already taken.` });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    res.status(201).json({
      message: `Registration successful for ${savedUser.username}. Please login.`,
      user: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email
      }
    });
}));

// ------------------------- LOGIN ROUTE -------------------------
app.post('/api/auth/login', routeHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password.' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' }); 
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' }); 
    }

    const payload = {
      user: {
        id: user.id,
        username: user.username,
      },
    };

    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET_MISSING'); 
    }

    jwt.sign(
      payload,
      JWT_SECRET,
      { expiresIn: '1h' },
      (err, token) => {
        if (err) {
           console.error('JWT Signing Error:', err);
           return res.status(500).json({ message: 'Token generation failed.' });
        }

        res.json({
          message: 'Login successful!',
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email
          }
        });
      }
    );
}));

// Fallback route for Vercel deployment structure
app.use((req, res) => {
    res.status(404).json({ message: 'API route not found.' });
});

module.exports = app;