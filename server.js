// =========================================================================
// 1. SETUP & IMPORTS
// =========================================================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// Backblaze B2 SDK for permanent storage
const B2 = require('backblaze-b2');

// =========================================================================
// 2. CONFIGURATION & ENVIRONMENT VARIABLES
// =========================================================================

require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRY = '30d'; // Set a long expiry for access token
const MONGODB_URI = process.env.MONGODB_URI;

// Backblaze B2 Configuration
const b2 = new B2({
    applicationKeyId: process.env.B2_APPLICATION_KEY_ID,
    applicationKey: process.env.B2_APPLICATION_KEY,
});
const B2_BUCKET_ID = process.env.B2_BUCKET_ID;
const B2_BUCKET_NAME = process.env.B2_BUCKET_NAME; // Used for path construction
const B2_ENDPOINT = process.env.B2_DOWNLOAD_ENDPOINT; // Your custom S3-compatible download endpoint

// =========================================================================
// 3. MIDDLEWARE
// =========================================================================

// Configure CORS for your frontend domain
const corsOptions = {
    origin: ['http://localhost:3000', 'https://outflickz.netlify.app'],
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));

// Global middleware to parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Multer setup for file upload (handling files in memory before B2 upload)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Define upload fields for Multer
const uploadFields = [
    { name: 'front-view-upload-1', maxCount: 1 },
    { name: 'back-view-upload-1', maxCount: 1 },
    { name: 'front-view-upload-2', maxCount: 1 },
    { name: 'back-view-upload-2', maxCount: 1 },
    { name: 'front-view-upload-3', maxCount: 1 },
    { name: 'back-view-upload-3', maxCount: 1 },
    { name: 'front-view-upload-4', maxCount: 1 },
    { name: 'back-view-upload-4', maxCount: 1 },
];

// =========================================================================
// 4. MONGOOSE SCHEMA AND MODELS
// =========================================================================

// Sub-Schema for Variations (used by all collections/products)
const VariationSchema = new mongoose.Schema({
    variationIndex: { type: Number, required: true },
    colorHex: { type: String }, // Used by Wears and Caps, optional for Pre-Order
    frontImageUrl: { type: String, required: true }, // The B2 file key/path
    backImageUrl: { type: String, required: true }, // The B2 file key/path
}, { _id: false });

// 4.1. User Schema
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    passwordHash: { type: String, required: true },
    firstName: { type: String, trim: true },
    lastName: { type: String, trim: true },
    username: { type: String, trim: true, unique: true, sparse: true },
    isVerified: { type: Boolean, default: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
}, { timestamps: true });

// 4.2. Wears Collection Schema (Standard/Existing Product)
const WearsCollectionSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    tag: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    sizes: { type: [String], required: true },
    totalStock: { type: Number, required: true, min: 0, default: 0 },
    isActive: { type: Boolean, default: true },
    variations: { type: [VariationSchema], required: true },
}, { timestamps: true });

// 4.3. New Arrivals Collection Schema (Similar to Wears)
const NewArrivalsSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    tag: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    sizes: { type: [String], required: true },
    totalStock: { type: Number, required: true, min: 0, default: 0 },
    isActive: { type: Boolean, default: true },
    variations: { type: [VariationSchema], required: true },
}, { timestamps: true });

// 4.4. Pre-Order Collection Schema (Includes Dates)
const PreOrderCollectionSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    tag: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    sizes: { type: [String], required: true },
    totalStock: { type: Number, required: true, min: 0, default: 0 },
    isActive: { type: Boolean, default: true },
    availableDate: { type: Date, required: true }, // Unified delivery/availability date
    variations: { type: [VariationSchema], required: true },
}, { timestamps: true });

// 4.5. Cap Collection Schema
const CapCollectionSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    tag: { type: String, required: true, trim: true },
    price: { type: Number, required: true, min: 0 },
    sizes: { type: [String], required: true, default: ['OSFA'] }, // One Size Fits All
    totalStock: { type: Number, required: true, min: 0, default: 0 },
    isActive: { type: Boolean, default: true },
    variations: { type: [VariationSchema], required: true },
}, { timestamps: true });

// Mongoose Models
const User = mongoose.model('User', UserSchema);
const WearsCollection = mongoose.model('WearsCollection', WearsCollectionSchema);
const NewArrivals = mongoose.model('NewArrivals', NewArrivalsSchema);
const PreOrderCollection = mongoose.model('PreOrderCollection', PreOrderCollectionSchema);
const CapCollection = mongoose.model('CapCollection', CapCollectionSchema);

// =========================================================================
// 5. B2 HELPER FUNCTIONS (File Storage)
// =========================================================================

/**
 * Uploads a file buffer to Backblaze B2.
 * @param {object} file - The file object from Multer (must be in memory).
 * @returns {Promise<string>} The B2 file key (path) of the uploaded file.
 */
async function uploadFileToPermanentStorage(file) {
    const fileExtension = path.extname(file.originalname);
    const fileName = `products/${uuidv4()}${fileExtension}`;

    const { data: uploadUrlData } = await b2.getUploadUrl({ bucketId: B2_BUCKET_ID });

    await b2.uploadFile({
        uploadUrl: uploadUrlData.uploadUrl,
        uploadAuthToken: uploadUrlData.authorizationToken,
        bucketId: B2_BUCKET_ID,
        fileName: fileName,
        data: file.buffer,
        contentLength: file.size,
        contentType: file.mimetype,
    });

    return fileName;
}

/**
 * Deletes a file from Backblaze B2 using its file key (path).
 * @param {string} fileKey - The B2 file key/path (e.g., 'products/uuid.jpg').
 */
async function deleteFileFromPermanentStorage(fileKey) {
    try {
        const { data: fileInfo } = await b2.getFileInfo({ bucketId: B2_BUCKET_ID, fileName: fileKey });

        await b2.deleteFileVersion({
            fileName: fileKey,
            fileId: fileInfo.fileId,
        });
        console.log(`Successfully deleted file: ${fileKey}`);
    } catch (error) {
        console.error(`Failed to delete file ${fileKey}:`, error.message);
        // Note: We "fire and forget" this, so failure here shouldn't block the API response.
    }
}

/**
 * Generates a signed, temporary URL for a private B2 file.
 * @param {string} fileKey - The B2 file key/path.
 * @returns {Promise<string>} The signed URL.
 */
async function generateSignedUrl(fileKey) {
    if (!fileKey) return null;

    // Use the custom S3-compatible endpoint for generating pre-signed URLs
    // This assumes your B2 is configured for S3 compatibility and the B2_ENDPOINT is the correct URL.
    // For direct B2 link, you'd use b2.getDownloadAuthorization, but for public read endpoint:

    // This implementation assumes a public bucket and simply constructs the path.
    // If your bucket is private, you must use getDownloadAuthorization and then construct the URL.
    try {
        // Construct URL using the custom download endpoint (better for CORS/CDNs)
        return `${B2_ENDPOINT}/${B2_BUCKET_NAME}/${fileKey}`;
    } catch (error) {
        console.error(`Error generating signed URL for ${fileKey}:`, error.message);
        return null;
    }
}


// =========================================================================
// 6. INITIAL DATA POPULATION
// =========================================================================

/**
 * Populates a default admin user if one doesn't exist.
 */
async function populateInitialData() {
    try {
        const adminEmail = 'admin@example.com';
        const adminUser = await User.findOne({ email: adminEmail });

        if (!adminUser) {
            const hashedPassword = await bcrypt.hash('password123', 10);
            const newAdmin = new User({
                email: adminEmail,
                passwordHash: hashedPassword,
                firstName: 'Admin',
                lastName: 'User',
                username: 'superadmin',
                isVerified: true,
                role: 'admin',
            });
            await newAdmin.save();
            console.log('Default Admin User Created.');
        }

        console.log('Initial data population complete.');
    } catch (error) {
        console.error('Error populating initial data:', error);
    }
}


// =========================================================================
// 7. AUTH MIDDLEWARE
// =========================================================================

/**
 * Middleware to verify a JWT token and set req.userId and req.role.
 */
function verifyToken(req, res, next) {
    let token = req.headers.authorization;

    if (!token) {
        return res.status(401).json({ message: 'Access Denied. No token provided.' });
    }

    if (token.startsWith('Bearer ')) {
        token = token.slice(7, token.length).trim();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        req.role = decoded.role; // Extract role from token
        next();
    } catch (error) {
        return res.status(403).json({ message: 'Invalid or expired token.' });
    }
}

/**
 * Middleware to check if the user is authenticated (logged in).
 */
function isAuthenticated(req, res, next) {
    // Reusing verifyToken logic, but you might want to separate them later
    verifyToken(req, res, next); 
}

/**
 * Middleware to check if the user is an admin.
 */
function isAdmin(req, res, next) {
    verifyToken(req, res, () => {
        if (req.role === 'admin') {
            next();
        } else {
            return res.status(403).json({ message: 'Access Denied. Admin privileges required.' });
        }
    });
}


// =========================================================================
// 8. AUTH ROUTES
// =========================================================================

// POST /api/register - Register a new user
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, username } = req.body;

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ message: 'Email or username already in use.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const newUser = new User({
            email,
            passwordHash,
            firstName,
            lastName,
            username,
            role: (email === 'admin@example.com' && username === 'superadmin') ? 'admin' : 'user',
            isVerified: false, // Default to false
        });

        await newUser.save();

        res.status(201).json({ message: 'Registration successful. Please verify your email.', userId: newUser._id });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// POST /api/login - Log in a user
app.post('/api/login', async (req, res) => {
    try {
        const { identifier, password } = req.body; // 'identifier' can be email or username

        // Find user by email or username
        const user = await User.findOne({
            $or: [{ email: identifier }, { username: identifier }]
        });

        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate JWT Token
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRY }
        );

        res.status(200).json({
            message: 'Login successful.',
            token: token,
            user: {
                id: user._id,
                email: user.email,
                username: user.username,
                role: user.role,
            }
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// =========================================================================
// 9. ADMIN ROUTES (/api/admin)
// =========================================================================

// --- CAP COLLECTION API ROUTES ---

// GET /api/admin/capcollections (Fetch All Collections) 
app.get(
    '/api/admin/capcollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections
            const collections = await CapCollection.find({})
                .select('_id name tag price variations totalStock isActive')
                .sort({ createdAt: -1 })
                .lean();

            // Sign URLs for all variations
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
            console.error('Error fetching cap collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);

// GET /api/admin/capcollections/:id (Fetch Single Collection)
app.get('/api/admin/capcollections/:id', verifyToken, async (req, res) => {
    try {
        const collection = await CapCollection.findById(req.params.id).lean();

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
        res.status(500).json({ message: 'Server error fetching collection.' });
    }
});

// POST /api/admin/capcollections (Create New Collection)
app.post(
    '/api/admin/capcollections',
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
            const newCollection = new CapCollection({
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price,
                sizes: collectionData.sizes || ['OSFA'],
                totalStock: collectionData.totalStock,
                isActive: collectionData.isActive,
                variations: finalVariations,
            });

            // D. Save to Database
            const savedCollection = await newCollection.save();

            res.status(201).json({
                message: 'Cap Collection created and images uploaded successfully to Backblaze B2.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating cap collection:', error);
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
            }
            res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/capcollections/:id (Update Collection)
app.put(
    '/api/admin/capcollections/:id',
    verifyToken,
    upload.fields(uploadFields),
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;

        try {
            existingCollection = await CapCollection.findById(collectionId);
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
            existingCollection.sizes = collectionData.sizes || ['OSFA'];
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
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);

// DELETE /api/admin/capcollections/:id (Delete Collection) 
app.delete('/api/admin/capcollections/:id', verifyToken, async (req, res) => {
    try {
        const collectionId = req.params.id;
        const deletedCollection = await CapCollection.findByIdAndDelete(collectionId);

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
        res.status(500).json({ message: 'Server error during collection deletion.' });
    }
});


// --- NEW ARRIVALS API ROUTES ---

// GET /api/admin/newarrivals (Fetch All New Arrivals)
app.get(
    '/api/admin/newarrivals',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all products
            const products = await NewArrivals.find({})
                .select('_id name tag price variations totalStock isActive')
                .sort({ createdAt: -1 })
                .lean();

            // Sign URLs for all variations
            const signedProducts = await Promise.all(products.map(async (product) => {
                const signedVariations = await Promise.all(product.variations.map(async (v) => ({
                    ...v,
                    frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                    backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
                })));
                return {
                    ...product,
                    variations: signedVariations
                };
            }));

            res.status(200).json(signedProducts);
        } catch (error) {
            console.error('Error fetching new arrivals:', error);
            res.status(500).json({ message: 'Server error while fetching new arrivals.', details: error.message });
        }
    }
);

// GET /api/admin/newarrivals/:id (Fetch Single New Arrival)
app.get('/api/admin/newarrivals/:id', verifyToken, async (req, res) => {
    try {
        const product = await NewArrivals.findById(req.params.id).lean();

        if (!product) {
            return res.status(404).json({ message: 'New Arrival not found.' });
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
        res.status(500).json({ message: 'Server error fetching new arrival.' });
    }
});

// POST /api/admin/newarrivals (Create New Arrival)
app.post(
    '/api/admin/newarrivals',
    verifyToken,
    upload.fields(uploadFields),
    async (req, res) => {
        try {
            // A. Extract JSON Metadata
            if (!req.body.productData) {
                return res.status(400).json({ message: "Missing new arrival data payload." });
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
                return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
            }

            // C. Create the Final Product Object
            const newProduct = new NewArrivals({
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
                message: 'New Arrival created and images uploaded successfully to Backblaze B2.',
                productId: savedProduct._id,
                name: savedProduct.name
            });

        } catch (error) {
            console.error('Error creating new arrival:', error);
            if (error.name === 'ValidationError') {
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors });
            }
            res.status(500).json({ message: 'Server error during product creation or file upload.', details: error.message });
        }
    }
);

// PUT /api/admin/newarrivals/:id (Update New Arrival)
app.put(
    '/api/admin/newarrivals/:id',
    verifyToken,
    upload.fields(uploadFields),
    async (req, res) => {
        const productId = req.params.id;
        let existingProduct;

        try {
            existingProduct = await NewArrivals.findById(productId);
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
            res.status(500).json({ message: 'Server error during product update or file upload.', details: error.message });
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


// --- WEARS COLLECTION API ROUTES ---

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


// --- PRE-ORDER COLLECTION API ROUTES ---

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
                throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
            }

            const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
            const uploadBackPromise = uploadFileToPermanentStorage(backFile);

            const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                .then(([frontImageUrl, backImageUrl]) => {
                    finalVariations.push({
                        variationIndex: variation.variationIndex,
                        // colorHex was removed in the previous step
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

        // C. Create the Final Collection Object (UPDATED: Using availableDate)
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

            // A. HANDLE QUICK UPDATE (Stock, Active Status)
            if (isQuickUpdate) {
                const { totalStock, isActive, availableDate } = req.body;

                const updateFields = {};
                if (totalStock !== undefined) updateFields.totalStock = totalStock;
                if (isActive !== undefined) updateFields.isActive = isActive;
                if (availableDate !== undefined) updateFields.availableDate = availableDate;


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
                    // Use functions for lazy evaluation of file URLs after uploads complete
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
            existingCollection.availableDate = collectionData.availableDate;

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
            // Fetch all collections
            const collections = await PreOrderCollection.find({})
                .select('_id name tag price variations totalStock isActive availableDate')
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
            
            // Delete associated images from Backblaze B2 (fire and forget)
            deletedCollection.variations.forEach(v => {
                if (v.frontImageUrl) deleteFileFromPermanentStorage(v.frontImageUrl);
                if (v.backImageUrl) deleteFileFromPermanentStorage(v.backImageUrl);
            });

            // Successful deletion
            res.status(200).json({
                message: 'Pre-order collection deleted successfully.',
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

// =========================================================================
// 10. PUBLIC ROUTES
// =========================================================================

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
        // 1. Fetch only collections that are active (isActive: true)
        const collections = await PreOrderCollection.find({ isActive: true })
            // Select all necessary fields from the Schema
            .select('_id name tag price sizes totalStock availableDate variations')
            .sort({ createdAt: -1 })
            .lean();

        // 2. Transform and Sign URLs for public frontend structure
        const publicCollections = await Promise.all(collections.map(async (collection) => {

            // Map Mongoose variations to a simpler public variants array and sign URLs
            const variants = await Promise.all(collection.variations.map(async (v) => ({
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
            })));

            // Return the transformed object matching the Caps/Wears format
            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price,
                availableSizes: collection.sizes,
                availableStock: collection.totalStock,
                availableDate: collection.availableDate,
                variants: variants
            };
        }));

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


// GET /api/usersaccount (For Current User Profile Display)
app.get('/api/usersaccount', isAuthenticated, async (req, res) => {
    try {
        // 1. Get the authenticated User ID
        const userId = req.userId;

        // 2. Fetch the User document by ID
        const user = await User.findById(userId)
            // Select ONLY the public fields needed for the frontend profile.
            .select('_id email firstName lastName username isVerified role createdAt updatedAt')
            .lean(); // Use .lean() for faster query results (plain JavaScript objects)

        // 3. Handle case where user is not found (Auth succeeded but record is missing)
        if (!user) {
            return res.status(404).json({ message: 'User account not found.' });
        }

        // 4. Transform and structure the response for the frontend
        const publicUserAccount = {
            id: user._id, // Use 'id' for frontend consistency
            profile: {
                email: user.email,
                firstName: user.firstName || 'N/A',
                lastName: user.lastName || 'N/A',
                username: user.username || 'N/A',
            },
            status: {
                role: user.role,
                isVerified: user.isVerified,
            },
            membership: {
                memberSince: user.createdAt,
                lastUpdated: user.updatedAt,
            }
        };

        // 5. Send the fully structured response
        res.status(200).json(publicUserAccount);

    } catch (error) {
        console.error('Error fetching user account details:', error);
        res.status(500).json({
            message: 'Server error while fetching user account details.',
            details: error.message
        });
    }
});


// =========================================================================
// 11. SERVER STARTUP
// =========================================================================

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log('MongoDB connected successfully.');
        // Populate initial data after connection (e.g., admin user)
        populateInitialData(); 
        
        // Start the server
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    })
    .catch(err => {
        console.error('MongoDB connection error:', err);
        // Exit process if DB connection fails
        process.exit(1); 
    });


// =========================================================================
// 12. NETLIFY EXPORTS
// =========================================================================

module.exports = {
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};