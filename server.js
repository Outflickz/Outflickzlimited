const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');

// --- BACKBLAZE B2 INTEGRATION (USING AWS SDK v3) ---
const { S3Client, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { Upload } = require('@aws-sdk/lib-storage');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner'); 

// Load environment variables (ensure these are set in your .env file)
dotenv.config();

// --- B2 CONFIGURATION ---
const BLAZE_ACCESS_KEY = process.env.BLAZE_ACCESS_KEY;
const BLAZE_SECRET_KEY = process.env.BLAZE_SECRET_KEY;
const BLAZE_ENDPOINT = process.env.BLAZE_ENDPOINT;
const BLAZE_BUCKET_NAME = process.env.BLAZE_BUCKET_NAME;

// Initialize the S3 Client configured for Backblaze B2
const s3Client = new S3Client({
    endpoint: BLAZE_ENDPOINT,
    region: 'us-west-004', // The region is often implied by the endpoint, but good practice to include
    credentials: {
        accessKeyId: BLAZE_ACCESS_KEY,
        secretAccessKey: BLAZE_SECRET_KEY,
    },
    // Required for Backblaze B2's S3-compatibility layer
    forcePathStyle: true,
});

/**
 * Generates a temporary, pre-signed URL for private files in Backblaze B2.
 * @param {string} fileUrl - The permanent B2 URL.
 * @returns {Promise<string|null>} The temporary signed URL, or null if key extraction fails.
 */
async function generateSignedUrl(fileUrl) {
    if (!fileUrl) return null;

    try {
        // 1. Extract the Key (path after BLAZE_BUCKET_NAME) from the URL
        const urlObj = new URL(fileUrl);
        const pathSegments = urlObj.pathname.split('/');
        
        // Find the index of the bucket name, and take everything after it.
        const bucketNameIndex = pathSegments.findIndex(segment => segment === BLAZE_BUCKET_NAME);
        if (bucketNameIndex === -1) {
            console.warn(`[Signed URL] Bucket name not found in path: ${fileUrl}`);
            return null;
        }

        // The file key is everything after the bucket name
        const fileKey = pathSegments.slice(bucketNameIndex + 1).join('/');

        if (!fileKey) {
            console.warn(`[Signed URL] Could not determine file key from URL: ${fileUrl}`);
            return null;
        }

        // 2. Create the GetObject command
        const command = new GetObjectCommand({
            Bucket: BLAZE_BUCKET_NAME,
            Key: fileKey,
        });

        // 3. Generate the signed URL (expires in 300 seconds = 5 minutes)
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });

        return signedUrl;

    } catch (error) {
        // Log the failure but don't crash the server
        console.error(`[Signed URL] Failed to generate signed URL for ${fileUrl}:`, error);
        return null;
    }
}


/**
 * Uploads a file buffer (from Multer memory storage) to Backblaze B2.
 * @param {object} file - The file object from Multer (must contain `buffer`, `originalname`, and `mimetype`).
 * @returns {Promise<string>} The public URL of the uploaded file (this is the permanent, private path).
 */
async function uploadFileToPermanentStorage(file) {
    console.log(`[Backblaze B2] Starting upload for: ${file.originalname}`);

    // !!! CRITICAL: We DO NOT set ACL to public-read here, ensuring the bucket stays private.
    const fileKey = `wearscollections/${Date.now()}-${Math.random().toString(36).substring(2)}-${file.originalname.replace(/\s/g, '_')}`;

    const params = {
        Bucket: BLAZE_BUCKET_NAME,
        Key: fileKey,
        Body: file.buffer,
        ContentType: file.mimetype,
    };

    try {
        const uploader = new Upload({
            client: s3Client,
            params: params,
        });

        const result = await uploader.done();

        // Construct the permanent, private URL which we will store in MongoDB
        const permanentUrl = `${BLAZE_ENDPOINT}/${BLAZE_BUCKET_NAME}/${fileKey}`;

        console.log(`[Backblaze B2] Upload success. Location: ${result.Location}`);
        console.log(`[Backblaze B2] Permanent URL stored in DB: ${permanentUrl}`);

        return permanentUrl;

    } catch (error) {
        console.error("Backblaze B2 Upload Error:", error);
        throw new Error(`Failed to upload file to Backblaze B2: ${error.message}`);
    }
}

/**
 * Deletes a file from Backblaze B2 given its URL.
 * @param {string} fileUrl - The permanent B2 URL of the file to delete.
 */
async function deleteFileFromPermanentStorage(fileUrl) {
    if (!fileUrl) return;

    try {
        // Extract the Key (path after BLAZE_BUCKET_NAME) from the URL
        const urlObj = new URL(fileUrl);
        const pathSegments = urlObj.pathname.split('/');
        
        const bucketNameIndex = pathSegments.findIndex(segment => segment === BLAZE_BUCKET_NAME);
        if (bucketNameIndex === -1) {
            console.warn(`[Delete] Bucket name not found in path: ${fileUrl}`);
            return;
        }
        const fileKey = pathSegments.slice(bucketNameIndex + 1).join('/');
        
        if (!fileKey) {
             console.warn(`Could not determine file key from URL: ${fileUrl}`);
             return;
        }

        console.log(`[Backblaze B2] Deleting file with Key: ${fileKey}`);

        const command = new DeleteObjectCommand({
            Bucket: BLAZE_BUCKET_NAME,
            Key: fileKey,
        });

        await s3Client.send(command);
        console.log(`[Backblaze B2] Deletion successful for key: ${fileKey}`);
    } catch (error) {
        // Log the error but don't stop the main process if deletion fails
        console.error(`[Backblaze B2] Failed to delete file at ${fileUrl}:`, error);
    }
}
// -----------------------------------------------------------------


// --- CONFIGURATION ---
const MONGODB_URI = process.env.MONGODB_URI
const JWT_SECRET = process.env.JWT_SECRET
const BCRYPT_SALT_ROUNDS = 10;

// Default admin credentials
const DEFAULT_ADMIN_EMAIL = process.env.DEFAULT_ADMIN_EMAIL
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD


// --- MONGODB SCHEMAS & MODELS ---
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);


// --- Product Variation Sub-Schema (Supporting Dual Images) ---

const ProductVariationSchema = new mongoose.Schema({
    variationIndex: { 
        type: Number, 
        required: true, 
        min: 1, 
        max: 4 
    },
    
    frontImageUrl: { 
        type: String, 
        required: [true, 'Front view image URL is required'], // Stores the permanent B2 URL
        trim: true 
    }, 
    backImageUrl: { 
        type: String, 
        required: [true, 'Back view image URL is required'], // Stores the permanent B2 URL
        trim: true 
    }, 
    
    colorHex: { 
        type: String, 
        required: [true, 'Color Hex code is required'], 
        // Standard full hex code validation
        match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex code (e.g., #RRGGBB)'] 
    }
}, { _id: false });


// --- Main Wears Collection Schema ---

const WearsCollectionSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Collection name is required'],
        trim: true,
        maxlength: [100, 'Collection name cannot exceed 100 characters']
    },
    tag: {
        type: String,
        required: [true, 'Collection tag is required'],
        enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance']
    },
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema],
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    },
    sizes: {
        type: [String],
        required: [true, 'Available sizes are required'],
        validate: {
            validator: function(v) { return Array.isArray(v) && v.length > 0; },
            message: 'Sizes array cannot be empty.'
        }
    },
    totalStock: {
        type: Number,
        required: [true, 'Total stock number is required'],
        min: [0, 'Stock cannot be negative'],
        default: 0
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});


// --- Pre-Save Middleware (WearsCollection) ---

WearsCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    if (this.isActive === false) {
        this.totalStock = 0;
    }
    
    next();
});

const WearsCollection = mongoose.models.WearsCollection || mongoose.model('WearsCollection', WearsCollectionSchema);

// --- Main New Arrivals Schema (Identical structure to WearsCollection) ---
const NewArrivalsSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Product name is required'],
        trim: true,
        maxlength: [100, 'Product name cannot exceed 100 characters']
    },
    tag: {
        type: String,
        required: [true, 'Product tag is required'],
        enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance']
    },
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema],
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A product must have between 1 and 4 variations.'
        }
    },
    sizes: {
        type: [String],
        required: [true, 'Available sizes are required'],
        validate: {
            validator: function(v) { return Array.isArray(v) && v.length > 0; },
            message: 'Sizes array cannot be empty.'
        }
    },
    totalStock: {
        type: Number,
        required: [true, 'Total stock number is required'],
        min: [0, 'Stock cannot be negative'],
        default: 0
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// --- Pre-Save Middleware (NewArrivals) ---
NewArrivalsSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    if (this.isModified('isActive') && this.isActive === false) {
        this.totalStock = 0;
    }
    
    next();
});

const NewArrivals = mongoose.models.NewArrivals || mongoose.model('NewArrivals', NewArrivalsSchema);

// --- 🧢 NEW CAP COLLECTION SCHEMA AND MODEL 🧢 ---
// This uses the identical ProductVariationSchema as Wears and NewArrivals.
const CapCollectionSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Collection name is required'],
        trim: true,
        maxlength: [100, 'Collection name cannot exceed 100 characters']
    },
    tag: {
        type: String,
        required: [true, 'Collection tag is required'],
        enum: ['Top Deal', 'Hot Deal', 'New', 'Seasonal', 'Clearance']
    },
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema],
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    },
    totalStock: {
        type: Number,
        required: [true, 'Total stock number is required'],
        min: [0, 'Stock cannot be negative'],
        default: 0
    },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// --- Pre-Save Middleware (CapCollection) ---

CapCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    if (this.isActive === false) {
        this.totalStock = 0;
    }
    
    next();
});

const CapCollection = mongoose.models.CapCollection || mongoose.model('CapCollection', CapCollectionSchema);

const PreOrderCollectionSchema = new mongoose.Schema({
    // General Product Information
    name: { type: String, required: true, trim: true },
    tag: { type: String, required: true },
    price: { type: Number, required: true, min: 0 },
    sizes: { type: [String], required: true }, // e.g., ['S', 'M', 'L']
    totalStock: { type: Number, required: true, min: 0 },
    isActive: { type: Boolean, default: true },

    // New Availability Field
    availableDate: { 
        type: Date, 
        required: true, 
        // This is the date the pre-ordered item is expected to be available/shipped, 
        // or the date it becomes generally available.
    }, 

    // Variations (Colors, Images)
    variations: [
        {
            variationIndex: { type: Number, required: true },
            frontImageUrl: { type: String, required: true },
            backImageUrl: { type: String, required: true },
        }
    ]
}, { timestamps: true });

const PreOrderCollection = mongoose.model('PreOrderCollection', PreOrderCollectionSchema);

// --- DATABASE INTERACTION FUNCTIONS (Unchanged) ---
async function findAdminUserByEmail(email) {
    const adminUser = await Admin.findOne({ email }).select('+password').lean();
    if (adminUser) {
        return { id: adminUser._id, email: adminUser.email, hashedPassword: adminUser.password };
    }
    return null;
}

async function createAdminUser(email, hashedPassword) {
    try {
        const newAdmin = await Admin.create({ email, password: hashedPassword });
        return { id: newAdmin._id, email: newAdmin.email };
    } catch (error) {
        console.error("Error creating admin user:", error);
        return null;
    }
}

async function getRealTimeDashboardStats() {
    // Placeholder for actual stat fetching
    return { totalSales: 0, pendingOrders: 0, outOfStockItems: 0, userCount: 0 };
}

async function populateInitialData() {
    if (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD) {
        console.warn('Skipping initial data population: Default admin credentials not fully set.');
        return;
    }

    try {
        const adminCount = await Admin.countDocuments({ email: DEFAULT_ADMIN_EMAIL });
        
        if (adminCount === 0) {
            console.log(`Default admin user (${DEFAULT_ADMIN_EMAIL}) not found. Creating...`);
            
            const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
            const hashedPassword = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, salt);

            await Admin.create({ email: DEFAULT_ADMIN_EMAIL, password: hashedPassword });
            console.log(`Default admin user created successfully.`);
        } else {
            console.log(`Default admin user already exists. Skipping creation.`);
        }
    } catch (error) {
        console.error('Error during initial data population:', error);
    }
}


// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();
// Ensure express.json() is used BEFORE the update route, but after the full form route
// To allow both JSON and multipart/form-data parsing
app.use(express.json()); 

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => { res.redirect('/outflickzstore/homepage.html'); });
app.get('/admin-login', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-login.html')); });
app.get('/admin-dashboard', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-dashboard.html')); });
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'wearscollection.html')); });
// --- NEW ADMIN PAGE ROUTE ---
app.get('/capscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'capscollection.html')); }); // Assumes you create this HTML file


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

const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Define the expected file fields dynamically (e.g., front-view-upload-1, back-view-upload-1, up to index 4)
const uploadFields = Array.from({ length: 4 }, (_, i) => [
    { name: `front-view-upload-${i + 1}`, maxCount: 1 },
    { name: `back-view-upload-${i + 1}`, maxCount: 1 }
]).flat();


// --- GENERAL ADMIN API ROUTES ---
app.post('/api/admin/register', async (req, res) => {
    // ... registration logic
    res.status(501).json({ message: 'Registration is not yet implemented.' });
});

app.post('/api/admin/login', async (req, res) => {
    // ... login logic
    const { email, password } = req.body;
    try {
        const adminUser = await findAdminUserByEmail(email);
        if (!adminUser || !(await bcrypt.compare(password, adminUser.hashedPassword))) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        
        const token = jwt.sign(
            { id: adminUser.id, email: adminUser.email, role: 'admin' }, 
            JWT_SECRET, 
            { expiresIn: '24h' }
        );
        
        res.status(200).json({ token, message: 'Login successful' });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/api/admin/forgot-password', async (req, res) => {
    res.status(200).json({ message: 'If an account with that email address exists, a password reset link has been sent.' });
});

app.get('/api/admin/dashboard/stats', verifyToken, async (req, res) => {
    try {
        const stats = await getRealTimeDashboardStats();
        res.status(200).json(stats);
    } catch (error) {
        res.status(500).json({ message: 'Failed to retrieve dashboard stats.' });
    }
});

// -----------------------------------------------------------------
// 🧢 CAP COLLECTION API ROUTES (CRUD) 🧢
// -----------------------------------------------------------------

// GET /api/admin/capscollections - Fetch All Cap Collections
app.get('/api/admin/capscollections', verifyToken, async (req, res) => {
    try {
        // 1. Fetch all collections
        const collections = await CapCollection.find({})
            .select('_id name tag price variations totalStock isActive')
            .sort({ createdAt: -1 })
            .lean();

        // 2. Sign URLs for all collections
        const signedCollections = await Promise.all(collections.map(async (collection) => {
            const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                ...v,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
            })));
            return { ...collection, variations: signedVariations };
        }));

        res.status(200).json(signedCollections);
    } catch (error) {
        console.error('Error fetching cap collections:', error);
        res.status(500).json({ message: 'Server error while fetching cap collections.', details: error.message });
    }
});

// GET /api/admin/capscollections/:id - Fetch Single Cap Collection
app.get('/api/admin/capscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const collection = await CapCollection.findById(collectionId).lean();

        if (!collection) {
            return res.status(404).json({ message: 'Cap Collection not found.' });
        }

        // Sign URLs
        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;

        res.status(200).json(collection);
    } catch (error) {
        console.error('Error fetching cap collection:', error);
        res.status(500).json({ message: 'Server error fetching cap collection data.' });
    }
});

// POST /api/admin/capscollections - Create New Cap Collection
app.post(
    '/api/admin/capscollections',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload." });
            }
            const collectionData = JSON.parse(req.body.collectionData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of collectionData.variations) {
                const index = variation.variationIndex;
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received." });
            }

            // C. Create the Final Product Object
            const newCollection = new CapCollection({ // <-- Use CapCollection Model
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price, 
                sizes: collectionData.sizes,
                totalStock: collectionData.totalStock,
                isActive: collectionData.isActive,
                variations: finalVariations, 
            });

            // D. Save to Database
            const savedCollection = await newCollection.save();

            res.status(201).json({ 
                message: 'Cap Collection created successfully and images uploaded to B2.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating cap collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during cap collection creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/capscollections/:id - Update Cap Collection
app.put(
    '/api/admin/capscollections/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await CapCollection.findById(collectionId); // <-- Use CapCollection Model
            if (!existingCollection) {
                return res.status(404).json({ message: 'Cap Collection not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            
            // A. HANDLE QUICK RESTOCK (JSON only)
            if (isQuickRestock && !req.body.collectionData) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // Perform simple update
                existingCollection.totalStock = totalStock;
                existingCollection.isActive = isActive; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Cap Collection quick-updated. Stock: ${updatedCollection.totalStock}, Active: ${updatedCollection.isActive}.`,
                    collectionId: updatedCollection._id
                });
            }
            
            // B. HANDLE FULL FORM SUBMISSION (Multipart/form-data)
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    throw new Error(`Front image missing for Variation #${index}.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    throw new Error(`Back image missing for Variation #${index}.`);
                }
                
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            existingCollection.sizes = collectionData.sizes;
            existingCollection.totalStock = collectionData.totalStock;
            existingCollection.isActive = collectionData.isActive;
            
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                frontImageUrl: v.frontImageUrl, 
                backImageUrl: v.backImageUrl, 
            }));
            
            // Save to Database
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'Cap Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating cap collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during cap collection update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/capscollections/:id - Delete Cap Collection
app.delete('/api/admin/capscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const deletedCollection = await CapCollection.findByIdAndDelete(collectionId); // <-- Use CapCollection Model

        if (!deletedCollection) {
            return res.status(404).json({ message: 'Cap Collection not found for deletion.' });
        }

        // Delete associated images from Backblaze B2 (fire and forget)
        deletedCollection.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `Cap Collection ${collectionId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting cap collection:', error);
        res.status(500).json({ message: 'Server error during cap collection deletion.' });
    }
});


// --- NEW ARRIVALS API ROUTES (Existing) ---
// ... (The New Arrivals CRUD routes remain here) ...
// GET /api/admin/newarrivals - Fetch All New Arrivals
app.get('/api/admin/newarrivals', verifyToken, async (req, res) => {
    try {
        // 1. Fetch all products
        const products = await NewArrivals.find({})
            .select('_id name tag price variations totalStock isActive')
            .sort({ createdAt: -1 })
            .lean();

        // 2. Sign URLs for all products
        const signedProducts = await Promise.all(products.map(async (product) => {
            const signedVariations = await Promise.all(product.variations.map(async (v) => ({
                ...v,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
            })));
            return { ...product, variations: signedVariations };
        }));

        res.status(200).json(signedProducts);
    } catch (error) {
        console.error('Error fetching new arrivals:', error);
        res.status(500).json({ message: 'Server error while fetching new arrivals.', details: error.message });
    }
});

// GET /api/admin/newarrivals/:id - Fetch Single New Arrival
app.get('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const productId = req.params.id;
        const product = await NewArrivals.findById(productId).lean();

        if (!product) {
            return res.status(404).json({ message: 'Product not found.' });
        }

        // Sign URLs
        const signedVariations = await Promise.all(product.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        product.variations = signedVariations;

        res.status(200).json(product);
    } catch (error) {
        console.error('Error fetching new arrival:', error);
        res.status(500).json({ message: 'Server error fetching product data.' });
    }
});

// POST /api/admin/newarrivals - Create New Arrival
app.post(
    '/api/admin/newarrivals',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.productData) {
                return res.status(400).json({ message: "Missing product data payload." });
            }
            const productData = JSON.parse(req.body.productData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of productData.variations) {
                const index = variation.variationIndex;
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received." });
            }

            // C. Create the Final Product Object
            const newProduct = new NewArrivals({ // <-- Use NewArrivals Model
                name: productData.name,
                tag: productData.tag,
                price: productData.price, 
                sizes: productData.sizes,
                totalStock: productData.totalStock,
                isActive: productData.isActive,
                variations: finalVariations, 
            });

            // D. Save to Database
            const savedProduct = await newProduct.save();

            res.status(201).json({ 
                message: 'New Arrival created successfully and images uploaded to B2.',
                productId: savedProduct._id,
                name: savedProduct.name
            });

        } catch (error) {
            console.error('Error creating new arrival:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during new arrival creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/newarrivals/:id - Update New Arrival
app.put(
    '/api/admin/newarrivals/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const productId = req.params.id;
        let existingProduct;
        
        try {
            existingProduct = await NewArrivals.findById(productId); // <-- Use NewArrivals Model
            if (!existingProduct) {
                return res.status(404).json({ message: 'New Arrival not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            
            // A. HANDLE QUICK RESTOCK
            if (isQuickRestock && !req.body.productData) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // Perform simple update
                existingProduct.totalStock = totalStock;
                existingProduct.isActive = isActive; 

                const updatedProduct = await existingProduct.save();
                return res.status(200).json({ 
                    message: `New Arrival quick-updated. Stock: ${updatedProduct.totalStock}, Active: ${updatedProduct.isActive}.`,
                    productId: updatedProduct._id
                });
            }
            // B. HANDLE FULL FORM SUBMISSION
            if (!req.body.productData) {
                return res.status(400).json({ message: "Missing product data payload for full update." });
            }

            const productData = JSON.parse(req.body.productData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of productData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingProduct.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    throw new Error(`Front image missing for Variation #${index}.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    throw new Error(`Back image missing for Variation #${index}.`);
                }
                
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingProduct.name = productData.name;
            existingProduct.tag = productData.tag;
            existingProduct.price = productData.price;
            existingProduct.sizes = productData.sizes;
            existingProduct.totalStock = productData.totalStock;
            existingProduct.isActive = productData.isActive;
            
            existingProduct.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                frontImageUrl: v.frontImageUrl, 
                backImageUrl: v.backImageUrl, 
            }));
            
            // Save to Database
            const updatedProduct = await existingProduct.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'New Arrival updated and images handled successfully.',
                productId: updatedProduct._id,
                name: updatedProduct.name
            });

        } catch (error) {
            console.error('Error updating new arrival:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during new arrival update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/newarrivals/:id - Delete New Arrival
app.delete('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const productId = req.params.id;
        const deletedProduct = await NewArrivals.findByIdAndDelete(productId); // <-- Use NewArrivals Model

        if (!deletedProduct) {
            return res.status(404).json({ message: 'New Arrival not found for deletion.' });
        }

        // Delete associated images from Backblaze B2 (fire and forget)
        deletedProduct.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `New Arrival ${productId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting new arrival:', error);
        res.status(500).json({ message: 'Server error during product deletion.' });
    }
});
// -----------------------------------------------------------------


// --- WEARS COLLECTION API ROUTES (Existing) ---

// GET /api/admin/wearscollections/:id (Fetch Single Collection)
app.get('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        const collection = await WearsCollection.findById(req.params.id).lean(); 
        
        if (!collection) {
            return res.status(404).json({ message: 'Collection not found.' });
        }

        // Sign URLs
        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;

        res.status(200).json(collection);
    } catch (error) {
        console.error('Error fetching wear collection:', error);
        res.status(500).json({ message: 'Server error fetching collection.' });
    }
});

// POST /api/admin/wearscollections (Create New Collection) 
app.post(
    '/api/admin/wearscollections',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload." });
            }
            const collectionData = JSON.parse(req.body.collectionData);

            // B. Process Files and Integrate Paths into Variations
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            for (const variation of collectionData.variations) {
                const index = variation.variationIndex;
                const frontFile = files[`front-view-upload-${index}`]?.[0];
                const backFile = files[`back-view-upload-${index}`]?.[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
            }

            // C. Create the Final Collection Object
            const newCollection = new WearsCollection({
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price, 
                sizes: collectionData.sizes,
                totalStock: collectionData.totalStock,
                isActive: collectionData.isActive, 
                variations: finalVariations, 
            });

            // D. Save to Database
            const savedCollection = await newCollection.save();

            res.status(201).json({ 
                message: 'Wears Collection created and images uploaded successfully to Backblaze B2.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating wear collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/wearscollections/:id (Update Collection)
app.put(
    '/api/admin/wearscollections/:id',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await WearsCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Collection not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            
            // A. HANDLE QUICK RESTOCK
            if (isQuickRestock && !req.body.collectionData) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // Perform simple update
                existingCollection.totalStock = totalStock;
                existingCollection.isActive = isActive; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Collection quick-updated. Stock: ${updatedCollection.totalStock}, Active: ${updatedCollection.isActive}.`,
                    collectionId: updatedCollection._id
                });
            }

            // B. HANDLE FULL FORM SUBMISSION
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }
                
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            existingCollection.sizes = collectionData.sizes;
            existingCollection.totalStock = collectionData.totalStock;
            existingCollection.isActive = collectionData.isActive;
            
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                frontImageUrl: v.frontImageUrl, 
                backImageUrl: v.backImageUrl, 
            }));
            
            // Save to Database
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({ 
                message: 'Wears Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating wear collection:', error); 
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/wearscollections/:id (Delete Collection) 
app.delete('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const deletedCollection = await WearsCollection.findByIdAndDelete(collectionId);

        if (!deletedCollection) {
            return res.status(404).json({ message: 'Collection not found for deletion.' });
        }

        // Delete associated images from Backblaze B2 (fire and forget)
        deletedCollection.variations.forEach(v => {
            if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
            if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
        });

        res.status(200).json({ message: `Collection ${collectionId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting wear collection:', error);
        res.status(500).json({ message: 'Server error during collection deletion.' });
    }
});

// GET /api/admin/wearscollections (Fetch All Collections) 
app.get(
    '/api/admin/wearscollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections
            const collections = await WearsCollection.find({})
                .select('_id name tag price variations totalStock isActive')
                .sort({ createdAt: -1 })
                .lean(); 

            // Sign URLs
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                    backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
                })));
                return {
                    ...collection,
                    variations: signedVariations
                };
            }));

            res.status(200).json(signedCollections);
        } catch (error) {
            console.error('Error fetching wear collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);

// POST /api/admin/preordercollections (Create New Pre-Order Collection) 
app.post('/api/admin/preordercollections', verifyToken, upload.fields(uploadFields), async (req, res) => {
    try {
        // A. Extract JSON Metadata
        if (!req.body.collectionData) {
            return res.status(400).json({ message: "Missing pre-order collection data payload." });
        }
        const collectionData = JSON.parse(req.body.collectionData);

        // B. Process Files and Integrate Paths into Variations
        const files = req.files;
        const finalVariations = [];
        const uploadPromises = [];

        for (const variation of collectionData.variations) {
            const index = variation.variationIndex;
            const frontFile = files[`front-view-upload-${index}`]?.[0];
            const backFile = files[`back-view-upload-${index}`]?.[0];

            if (!frontFile || !backFile) {
                // If the incoming variation requires new files but they are missing, throw an error.
                throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
            }

            const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
            const uploadBackPromise = uploadFileToPermanentStorage(backFile);

            const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                .then(([frontImageUrl, backImageUrl]) => {
                    finalVariations.push({
                        variationIndex: variation.variationIndex,
                        frontImageUrl: frontImageUrl,
                        backImageUrl: backImageUrl,
                    });
                });

            uploadPromises.push(combinedUploadPromise);
        }

        await Promise.all(uploadPromises);

        if (finalVariations.length === 0) {
            return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
        }

        // C. Create the Final Collection Object (Using availableDate)
        const newCollection = new PreOrderCollection({
            name: collectionData.name,
            tag: collectionData.tag,
            price: collectionData.price,
            sizes: collectionData.sizes,
            totalStock: collectionData.totalStock,
            isActive: collectionData.isActive,
            availableDate: collectionData.availableDate, // Using the new unified date field
            variations: finalVariations,
        });

        // D. Save to Database
        const savedCollection = await newCollection.save();

        res.status(201).json({
            message: 'Pre-Order Collection created and images uploaded successfully.',
            collectionId: savedCollection._id,
            name: savedCollection.name
        });

    } catch (error) {
        console.error('Error creating pre-order collection:', error);
        if (error.name === 'ValidationError') {
            const messages = Object.values(error.errors).map(err => err.message).join(', ');
            return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
        }
        res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
    }
}
);


// PUT /api/admin/preordercollections/:id (Update Pre-Order Collection)
app.put(
    '/api/admin/preordercollections/:id',
    verifyToken,
    upload.fields(uploadFields),
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;

        try {
            existingCollection = await PreOrderCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Pre-Order Collection not found for update.' });
            }

            // Check if it's a simple update (JSON content-type and no collectionData for full form)
            const isQuickUpdate = req.get('Content-Type')?.includes('application/json') && !req.body.collectionData;

            // A. HANDLE QUICK UPDATE (Stock, Active Status, Available Date)
            if (isQuickUpdate) {
                // Correctly destructure and check for the unified date field
                const { totalStock, isActive, availableDate } = req.body;

                const updateFields = {};
                if (totalStock !== undefined) updateFields.totalStock = totalStock;
                if (isActive !== undefined) updateFields.isActive = isActive;
                if (availableDate !== undefined) updateFields.availableDate = availableDate; // Corrected

                if (Object.keys(updateFields).length === 0) {
                    return res.status(400).json({ message: "Missing update fields in simple update payload." });
                }

                // Perform simple update
                Object.assign(existingCollection, updateFields);

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({
                    message: `Pre-Order Collection quick-updated.`,
                    collectionId: updatedCollection._id,
                    updates: updateFields
                });
            }

            // B. HANDLE FULL FORM SUBMISSION (Includes Metadata and Files)
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files;
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    // New file uploaded: Schedule old file for deletion and new file for upload
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { finalFrontUrl = url; });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    // No new file and no existing URL means missing required data
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }

                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    // New file uploaded: Schedule old file for deletion and new file for upload
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { finalBackUrl = url; });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    // No new file and no existing URL means missing required data
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }

                // Push a placeholder object that will resolve once uploads complete
                updatedVariations.push({
                    variationIndex: index,
                    // Use functions for lazy evaluation of file URLs after uploads complete
                    get frontImageUrl() { return finalFrontUrl; },
                    get backImageUrl() { return finalBackUrl; },
                });
            }

            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                // If the update payload was valid but somehow resulted in no variations, reject.
                return res.status(400).json({ message: "No valid variations were processed for full update." });
            }

            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            existingCollection.sizes = collectionData.sizes;
            existingCollection.totalStock = collectionData.totalStock;
            existingCollection.isActive = collectionData.isActive;
            existingCollection.availableDate = collectionData.availableDate;

            // Map the placeholder objects to plain objects before saving
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                frontImageUrl: v.frontImageUrl,
                backImageUrl: v.backImageUrl,
            }));

            // Save to Database
            const updatedCollection = await existingCollection.save();

            // Delete old images in the background (fire and forget)
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            res.status(200).json({
                message: 'Pre-Order Collection updated and images handled successfully.',
                collectionId: updatedCollection._id,
                name: updatedCollection.name
            });

        } catch (error) {
            console.error('Error updating pre-order collection:', error);
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
            }
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);

// GET /api/admin/preordercollections (Fetch All Pre-Order Collections) 
app.get(
    '/api/admin/preordercollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections, selecting only necessary and consistent fields
            const collections = await PreOrderCollection.find({})
                // UPDATED: Using 'availableDate' and removing 'preorderDeadline'/'estimatedDelivery'
                .select('_id name tag price variations totalStock isActive availableDate') 
                .sort({ createdAt: -1 })
                .lean();

            // Sign URLs
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    // Handle potential null/undefined URLs gracefully
                    frontImageUrl: v.frontImageUrl ? await generateSignedUrl(v.frontImageUrl) : null, 
                    backImageUrl: v.backImageUrl ? await generateSignedUrl(v.backImageUrl) : null
                })));
                return {
                    ...collection,
                    variations: signedVariations
                };
            }));

            res.status(200).json(signedCollections);
        } catch (error) {
            console.error('Error fetching pre-order collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);

// DELETE /api/admin/preordercollections/:collectionId (Delete a Pre-Order Collection)
app.delete(
    '/api/admin/preordercollections/:collectionId',
    verifyToken, // Ensures only authorized users can delete
    async (req, res) => {
        const { collectionId } = req.params;

        try {
            // Find the collection by ID and delete it
            const deletedCollection = await PreOrderCollection.findByIdAndDelete(collectionId);

            // Check if the collection was found and deleted
            if (!deletedCollection) {
                return res.status(404).json({ message: 'Pre-order collection not found.' });
            }

            // NEW: Delete associated images in the background (fire and forget)
            deletedCollection.variations.forEach(v => {
                if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
                if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
            });

            // Successful deletion
            res.status(200).json({
                message: 'Pre-order collection deleted successfully and associated images scheduled for removal.',
                collectionId: collectionId
            });

        } catch (error) {
            // Handle common Mongoose errors (e.g., invalid ID format)
            if (error.name === 'CastError') {
                return res.status(400).json({ message: 'Invalid collection ID format.' });
            }

            console.error(`Error deleting collection ${collectionId}:`, error);
            res.status(500).json({ message: 'Server error during deletion.', details: error.message });
        }
    }
);

// --- PUBLIC ROUTES (Existing) ---

// GET /api/collections/wears (For Homepage Display)
app.get('/api/collections/wears', async (req, res) => {
    try {
        // Fetch only ACTIVE collections (WearsCollection)
        const collections = await WearsCollection.find({ isActive: true }) 
            .select('_id name tag price variations sizes totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        // Prepare the data for the public frontend
        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            // Map Mongoose variation to a simpler public variant object
            const variants = await Promise.all(collection.variations.map(async (v) => ({
                color: v.colorHex,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                backImageUrl: await generateSignedUrl(v.backImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error'
            })));

            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                availableSizes: collection.sizes,
                availableStock: collection.totalStock, 
                variants: variants
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public wear collections:', error);
        res.status(500).json({ message: 'Server error while fetching collections for homepage.', details: error.message });
    }
});

// GET /api/collections/newarrivals (For Homepage Display)
app.get('/api/collections/newarrivals', async (req, res) => {
    try {
        // Fetch only ACTIVE products (NewArrivals)
        const products = await NewArrivals.find({ isActive: true }) 
            .select('_id name tag price variations sizes totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        // Prepare the data for the public frontend
        const publicProducts = await Promise.all(products.map(async (product) => {
            
            // Map Mongoose variation to a simpler public variant object
            const variants = await Promise.all(product.variations.map(async (v) => ({
                color: v.colorHex,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                backImageUrl: await generateSignedUrl(v.backImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error'
            })));

            return {
                _id: product._id,
                name: product.name,
                tag: product.tag,
                price: product.price, 
                availableSizes: product.sizes,
                availableStock: product.totalStock, 
                variants: variants
            };
        }));

        res.status(200).json(publicProducts);
    } catch (error) {
        console.error('Error fetching public new arrivals:', error);
        res.status(500).json({ message: 'Server error while fetching new arrivals for homepage.', details: error.message });
    }
});

// --- NEW PUBLIC ROUTE FOR CAPS ---
// GET /api/collections/caps (For Homepage Display)
app.get('/api/collections/caps', async (req, res) => {
    try {
        // Fetch only ACTIVE collections (CapCollection)
        const collections = await CapCollection.find({ isActive: true }) 
            .select('_id name tag price variations sizes totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        // Prepare the data for the public frontend
        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            // Map Mongoose variation to a simpler public variant object
            const variants = await Promise.all(collection.variations.map(async (v) => ({
                color: v.colorHex,
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                backImageUrl: await generateSignedUrl(v.backImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error'
            })));

            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                availableSizes: collection.sizes,
                availableStock: collection.totalStock, 
                variants: variants
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public cap collections:', error);
        res.status(500).json({ message: 'Server error while fetching cap collections for homepage.', details: error.message });
    }
});
// GET /api/collections/preorder (For Homepage Display)
app.get('/api/collections/preorder', async (req, res) => {
    try {
        // 1. Fetch collections, selecting only the necessary metadata fields.
        // The 'variations' field is intentionally excluded as pre-order collections
        // do not use a color-based variation structure.
        const collections = await PreOrderCollection.find({ isActive: true })
            .select('_id name tag price sizes totalStock availableDate') 
            .sort({ createdAt: -1 })
            .lean();

        // 2. Transform the documents into the final public response structure.
        // No need to process variations or sign image URLs here since the homepage
        // display of pre-order items only needs the main metadata (name, price, date).
        const publicCollections = collections.map(collection => {
            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                // Rename for clarity on the frontend
                availableSizes: collection.sizes,
                availableStock: collection.totalStock, 
                availableDate: collection.availableDate, 
                // NOTE: 'variants' array is omitted as it contains no useful color data 
                // for the homepage card, preventing the frontend's createColorList from running.
            };
        });

        // 3. Send the fully structured response
        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public pre-order collections:', error);
        res.status(500).json({ 
            message: 'Server error while fetching public collections.', 
            details: error.message 
        });
    }
});


// --- NETLIFY EXPORTS for api.js wrapper ---
module.exports = {
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};