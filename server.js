const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const mongoose = require('mongoose');

// Load environment variables
dotenv.config();

// --- CONFIGURATION ---
const MONGO_URI = process.env.MONGO_URI 
const JWT_SECRET = process.env.JWT_SECRET 
const BCRYPT_SALT_ROUNDS = 10; 

// Default admin credentials for initial setup. Best practice is to use environment variables.
const DEFAULT_ADMIN_EMAIL = process.env.DEFAULT_ADMIN_EMAIL 
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD


// --- MONGODB SCHEMAS & MODELS ---
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    // 'select: false' ensures the password is not returned by default queries
    password: { type: String, required: true, select: false }, 
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);


// --- DATABASE INTERACTION FUNCTIONS ---

/**
 * Finds an admin user by email, explicitly including the password hash.
 * Assumes connection has already been established by the caller (api.js).
 */
async function findAdminUserByEmail(email) {
    // Note: Removed await connectDB() - connection is managed externally.
    const adminUser = await Admin.findOne({ email }).select('+password').lean();
    if (adminUser) {
        return { id: adminUser._id, email: adminUser.email, hashedPassword: adminUser.password };
    }
    return null;
}

/**
 * Creates a new admin user.
 * Assumes connection has already been established by the caller (api.js).
 */
async function createAdminUser(email, hashedPassword) {
    // Note: Removed await connectDB() - connection is managed externally.
    try {
        const newAdmin = await Admin.create({ email, password: hashedPassword });
        return { id: newAdmin._id, email: newAdmin.email };
    } catch (error) {
        console.error("Error creating admin user:", error);
        return null;
    }
}

/**
 * Placeholder for fetching real-time dashboard statistics.
 * Assumes connection has already been established by the caller (api.js).
 */
async function getRealTimeDashboardStats() {
    // Note: Removed await connectDB() - connection is managed externally.
    // Replace with actual database aggregation logic
    return { totalSales: 0, pendingOrders: 0, outOfStockItems: 0, userCount: 0 };
}

/**
 * Checks for the default admin user and creates it if it does not exist.
 * This is called once upon function warm-up in api.js.
 */
async function populateInitialData() {
    // Only proceed if the environment variables/defaults are set
    if (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD) {
        console.warn('Skipping initial data population: Default admin credentials not fully set.');
        return;
    }

    try {
        const adminCount = await Admin.countDocuments({ email: DEFAULT_ADMIN_EMAIL });
        
        if (adminCount === 0) {
            console.log(`Default admin user (${DEFAULT_ADMIN_EMAIL}) not found. Creating...`);
            
            // Hash the password
            const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
            const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, salt);

            // Create the user
            await Admin.create({ 
                email: DEFAULT_ADMIN_EMAIL, 
                password: hashedPassword 
            });
            console.log(`Default admin user created successfully.`);
        } else {
            console.log(`Default admin user already exists. Skipping creation.`);
        }
    } catch (error) {
        console.error('Error during initial data population:', error);
        // Do not re-throw if it's not a critical error (e.g., duplicate key in a race condition)
    }
}


// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();
app.use(express.json()); 

// --- 1. Static Files (ONLY serves from /public for local dev/testing) ---
app.use(express.static(path.join(__dirname, 'public')));


// --- 2. Frontend Routes ---
app.get('/', (req, res) => {
    res.redirect('/outflickzstore/homepage.html'); 
});
app.get('/admin', (req, res) => {
    res.redirect('/outflickzadmin/admin-login.html');
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
app.post('/api/admin/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password || password.length < 6) {
        return res.status(400).json({ message: 'Invalid input. Password must be at least 6 characters.' });
    }
    try {
        // Use the Admin model directly, assuming the connection is open
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
        res.status(200).json({ message: 'Login successful!', token: token });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An internal server error occurred during login.' });
    }
});

app.post('/api/admin/forgot-password', async (req, res) => {
    // Placeholder for email sending/password reset link logic
    res.status(200).json({ message: 'If an account with that email address exists, a password reset link has been sent.' });
});

app.get('/api/admin/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const stats = await getRealTimeDashboardStats();
        res.status(200).json(stats);
    } catch (error) {
        console.error('Dashboard Stats Error:', error);
        res.status(500).json({ message: 'Failed to fetch dashboard statistics from the database.' });
    }
});

// --- NETLIFY EXPORTS for api.js wrapper ---
// Note: We no longer export the handler directly. The wrapper in 
// netlify/functions/api.js handles the serverless execution and DB connection.
module.exports = {
    app,
    mongoose,
    populateInitialData,
    MONGO_URI // Exported in case it's needed by the wrapper (though api.js uses MONGODB_URI)
};