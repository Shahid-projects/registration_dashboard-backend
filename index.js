// =================================================================
//                      IMPORTS AND CONFIGURATION
// =================================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
// require('dotenv').config(); // Vercel manages this

// Initialize Express app
const app = express();

// =================================================================
//                           MIDDLEWARE
// =================================================================

// Ensure you replace 'https://registration-dashboard-frontend.vercel.app/' 
// with the exact base URL of your deployed frontend (without the trailing slash if possible).
const allowedOrigins = [
    'https://registration-dashboard-frontend.vercel.app', // Corrected: removed trailing slash
    'http://localhost:5000' 
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
        console.error('MONGO_URI is not defined. Check Vercel environment variables.');
        // Do NOT throw an error here, let the caller handle the check
        throw new Error('MONGO_URI_MISSING'); 
    }
    
    try {
        // Use options recommended for Vercel Serverless
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
 * NEW: Wrapper with complete error handling for database connection failures.
 */
const routeHandler = (handler) => async (req, res) => {
    try {
        await connectDb(); // Ensure connection before executing the handler
        await handler(req, res);
    } catch (error) {
        console.error("Route Handler Error:", error.message);

        if (error.message === 'MONGO_URI_MISSING') {
            return res.status(500).json({ 
                message: 'Server configuration error: Database URI is missing.' 
            });
        }
        
        if (error.message === 'DATABASE_CONNECTION_FAILED') {
            return res.status(503).json({ 
                message: 'Service temporarily unavailable: Cannot connect to database. Check MongoDB IP Whitelisting.' 
            });
        }

        // Handle Mongoose Duplicate Key Error (E11000)
        if (error.code === 11000) { 
            const field = Object.keys(error.keyPattern)[0];
            return res.status(409).json({
                message: `${field.charAt(0).toUpperCase() + field.slice(1)} already exists.`
            });
        }

        // Generic catch-all for unknown errors
        res.status(500).json({ message: 'Internal Server Error.' });
    }
};


// ------------------------- REGISTRATION ROUTE -------------------------
app.post('/api/auth/register', routeHandler(async (req, res) => {
    const { username, email, password } = req.body;

    // 1. Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Please provide all required fields.' });
    }

    // 2. Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      const field = existingUser.email.toLowerCase() === email.toLowerCase() ? 'Email' : 'Username';
      return res.status(409).json({ message: `${field} is already taken.` });
    }

    // 3. Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 4. Create and save the new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    // 5. Send a success response
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

    // 1. Validate input
    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password.' });
    }

    // 2. Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' }); 
    }

    // 3. Compare the provided password with the stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' }); 
    }

    // 4. Create JWT Payload
    const payload = {
      user: {
        id: user.id,
        username: user.username,
      },
    };

    // 5. Sign the token
    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET_MISSING'); // New check to throw a specific error
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

        // 6. Send token and user info to client
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

// Export the app for Vercel Serverless Function deployment
module.exports = app;