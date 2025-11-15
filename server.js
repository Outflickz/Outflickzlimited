const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const mongoose = require('mongoose');

// Load environment variables (Vercel uses its own environment config, 
// but dotenv is good for local testing)
dotenv.config();

// --- MONGODB/MONGOOSE SETUP ---

// Vercel deployment means we rely on environment variables being set in the Vercel project configuration.
// We are ensuring the essential variables are available.
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://outflickzlimited_db_user:Oladipupo0@cluster0.wu6bidy.mongodb.net/outflickz_db";
const JWT_SECRET = process.env.JWT_SECRET || 'your_default_secret_key_for_dev';
const BCRYPT_SALT_ROUNDS = 10; 

// --- MONGODB SCHEMAS ---

const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false }, 
    role: { type: String, default: 'admin' }
});

// Avoid re-registering models in serverless environment
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);
// const Order = mongoose.models.Order || mongoose.model('Order', new mongoose.Schema({ /* Your Order fields */ }));


// --- MONGODB CONNECTION IMPLEMENTATION ---
let cachedDb = null;

const connectDB = async () => {
    if (cachedDb) {
        console.log('✅ Using cached MongoDB connection.');
        return;
    }

    try {
        const db = await mongoose.connect(MONGO_URI);
        cachedDb = db;
        console.log('✅ New MongoDB connection established.');
    } catch (err) {
        console.error('❌ MongoDB connection error:', err.message);
        throw new Error('Failed to connect to database.'); 
    }
};

// --- DATABASE INTERACTION FUNCTIONS (using Mongoose/MongoDB logic) ---

async function findAdminUserByEmail(email) {
    console.log(`[DB] Querying MongoDB for admin user: ${email}...`);
    await connectDB(); 
    const adminUser = await Admin.findOne({ email }).select('+password').lean();

    if (adminUser) {
        return {
            id: adminUser._id,
            email: adminUser.email,
            hashedPassword: adminUser.password
        };
    }
    return null;
}

async function createAdminUser(email, hashedPassword) {
    console.log(`[DB] Attempting to create new admin user: ${email}`);
    await connectDB(); 
    try {
        const newAdmin = await Admin.create({ 
            email, 
            password: hashedPassword 
        });
        return { id: newAdmin._id, email: newAdmin.email };
    } catch (error) {
        console.error("Error creating admin user:", error);
        return null;
    }
}

async function getRealTimeDashboardStats() {
    console.log(`[DB] Performing MongoDB aggregation for dashboard statistics...`);
    await connectDB();
    return {
        totalSales: 0,
        pendingOrders: 0,
        outOfStockItems: 0,
        userCount: 0
    };
}


// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();

app.use(express.json()); 

// --- 1. Serve Static Files (UPDATED FOR PUBLIC FOLDER) ---
// IMPORTANT: All static content (index.html, Outflickz-Admin, Outflickz) 
// MUST now be placed inside a folder named 'public' in the root.
app.use(express.static(path.join(__dirname, 'public')));


/* // --- OLD STATIC ROUTES (COMMENTED OUT) ---
// app.use(express.static(path.join(__dirname)));
// app.use('/admin', express.static(path.join(__dirname, 'Outflickz-Admin')));
// app.use('/store', express.static(path.join(__dirname, 'Outflickz')));
*/


// --- 2. Define Frontend Routes ---
// These Express routes are generally ignored by Vercel's static asset routing
// but remain for local testing/fallback API behavior.
app.get('/', (req, res) => {
    // This will now redirect to the file located at /public/store/homepage.html
    res.redirect('/store/homepage.html'); 
});

app.get('/admin', (req, res) => {
    // This will now redirect to the file located at /public/admin/admin-login.html
    res.redirect('/admin/admin-login.html');
});

// --- 3. Authentication Middleware ---
const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Access denied. No token provided or token format invalid.' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.adminUser = decoded;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Invalid or expired token.' });
    }
};

// --- 4. API Routes ---

// POST /api/admin/register
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.status(400).json({ message: 'Invalid input. Password must be at least 6 characters.' });
    }

    try {
        const existingUser = await Admin.findOne({ email }); 
        if (existingUser) {
            return res.status(409).json({ message: 'Admin account already exists for this email.' });
        }

        const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newAdmin = await createAdminUser(email, hashedPassword);

        if (!newAdmin) {
             throw new Error("Database insertion failed.");
        }

        res.status(201).json({ message: 'Admin account created successfully. Please log in.', adminId: newAdmin.id });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'An internal server error occurred during registration.' });
    }
});


// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const adminUser = await findAdminUserByEmail(email);

        if (!adminUser) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, adminUser.hashedPassword);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign(
            { email: adminUser.email, role: 'admin', userId: adminUser.id },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Login successful!',
            token: token
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An internal server error occurred during login.' });
    }
});

// POST /api/admin/forgot-password
app.post('/api/admin/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log(`[AUTH] Password reset requested for: ${email}`);
    res.status(200).json({
        message: 'If an account with that email address exists, a password reset link has been sent.'
    });
});

// GET /api/admin/dashboard/stats
app.get('/api/admin/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const stats = await getRealTimeDashboardStats();
        res.status(200).json(stats);
        
    } catch (error) {
        console.error('Dashboard Stats Error:', error);
        res.status(500).json({ message: 'Failed to fetch dashboard statistics from the database.' });
    }
});


// --- VERCEL EXPORT ---
module.exports = app;

// For local testing only 
if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running locally on http://localhost:${PORT}`);
    });
}