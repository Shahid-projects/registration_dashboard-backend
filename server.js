// =================================================================
//                      IMPORTS AND CONFIGURATION
// =================================================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
// If you are using Vercel, .env variables are managed in the Vercel dashboard.
// require('dotenv').config(); 

// Initialize Express app
const app = express();

// =================================================================
//                           MIDDLEWARE
// =================================================================

// Configure CORS for security (allowing your Vercel frontend URL)
const allowedOrigins = [
    'https://registration-dashboard-frontend.vercel.app/', 
    'http://localhost:3000' // For local testing
];
app.use(cors({
    origin: (origin, callback) => {
        // Allow requests with no origin (like mobile apps or curl) or if the origin is in the allowed list
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));

app.use(express.json()); // Parse JSON request bodies

// =================================================================
//                        DATABASE CONNECTION
// =================================================================

const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Use a global connection variable to avoid reconnecting on every serverless function call
let isConnected;

const connectDb = async () => {
    if (isConnected) {
        console.log('=> Using existing database connection');
        return;
    }

    if (!MONGO_URI) {
        console.error('MONGO_URI is not defined. Check Vercel environment variables.');
        return;
    }
    
    try {
        await mongoose.connect(MONGO_URI);
        isConnected = true;
        console.log('=> New database connection established');
    } catch (err) {
        console.error('MongoDB connection error:', err.message);
        throw new Error('Failed to connect to the database.');
    }
};

// =================================================================
//                         DATABASE SCHEMA & MODEL
// =================================================================

const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
}, { timestamps: true });

// Prevent Mongoose from compiling the model multiple times in development/serverless environment
const User = mongoose.models.User || mongoose.model('User', UserSchema);

// =================================================================
//                            API ROUTES
// =================================================================

// Use a wrapper function for all routes to ensure DB connection is made
// From the corrected backend code:
// From the corrected backend code:
const routeHandler = (handler) => async (req, res) => {
    try {
        await connectDb(); // This ensures connection is attempted
        await handler(req, res);
    } catch (error) {
        // ... Error handling
    }
};

app.post('/api/auth/register', routeHandler(async (req, res) => {
    // ... your registration logic
}));

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
      const field = existingUser.email === email ? 'Email' : 'Username';
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
      return res.status(401).json({ message: 'Invalid credentials.' }); // Generic error for security
    }

    // 3. Compare the provided password with the stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' }); // Generic error for security
    }

    // 4. Create JWT Payload
    const payload = {
      user: {
        id: user.id,
        username: user.username, // Include username in token
      },
    };

    // 5. Sign the token
    if (!JWT_SECRET) {
        throw new Error('JWT_SECRET is not configured.');
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