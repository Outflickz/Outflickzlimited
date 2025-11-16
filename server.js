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
 * @param {string} fileUrl - The permanent B2 URL (e.g., https://s3.us-west-004.backblazeb2.com/bucket-name/path/to/file.jpg).
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


// --- MONGODB SCHEMAS & MODELS (UPDATED) ---
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);
// --- 1. Define the Updated Product Variation Sub-Schema (Supporting Dual Images) ---

const ProductVariationSchema = new mongoose.Schema({
    variationIndex: { 
        type: Number, 
        required: true, 
        min: 1, 
        max: 4 
    },
    
    // --- UPDATED FOR DUAL IMAGES ---
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
    // --- END OF DUAL IMAGE UPDATE ---
    
    colorHex: { 
        type: String, 
        required: [true, 'Color Hex code is required'], 
        // Standard full hex code validation
        match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex code (e.g., #RRGGBB)'] 
    }
}, { _id: false });


// --- 2. Define the Main Wears Collection Schema ---

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
    // Reference the updated ProductVariationSchema
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


// --- 3. Pre-Save Middleware (Updated to sync stock and active status) ---

WearsCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    
    // Logic to sync with frontend: If the collection is marked inactive, force stock to 0.
    if (this.isActive === false) {
        this.totalStock = 0;
    }
    
    next();
});

const WearsCollection = mongoose.models.WearsCollection || mongoose.model('WearsCollection', WearsCollectionSchema);


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


// --- EXPRESS CONFIGURATION AND MIDDLEWARE (Unchanged) ---
const app = express();
// Ensure express.json() is used BEFORE the update route, but after the full form route
// To allow both JSON and multipart/form-data parsing
app.use(express.json()); 

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => { res.redirect('/outflickzstore/homepage.html'); });
app.get('/admin-login', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-login.html')); });
app.get('/admin-dashboard', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-dashboard.html')); });
// Handles both creation and editing pages, client-side JS will look for an ID in the URL.
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'wearscollection.html')); });


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


// --- API Routes ---
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
// Assume the following are available in scope:
// const WearsCollection = require('./models/WearsCollection'); // Mongoose Model
// const verifyToken = require('./middleware/auth'); // Auth Middleware
// const upload = require('./middleware/multer'); // Multer config
// const { generateSignedUrl, uploadFileToPermanentStorage, deleteFileFromPermanentStorage } = require('./services/backblaze'); // B2 service functions

// --- 1. MODIFIED ROUTE: GET /api/admin/wearscollections/:id (Fetch Single Collection) ---
// Signs private image URLs before sending to client.
// UPDATED: Signs both frontImageUrl and backImageUrl.
// ------------------------------------------------------------------------------------------------

app.get('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        const collection = await WearsCollection.findById(req.params.id).lean(); // Use .lean() for easier modification
        
        if (!collection) {
            return res.status(404).json({ message: 'Collection not found.' });
        }

        // --- SIGN URLS HERE ---
        const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
            ...v,
            // Sign the front image URL
            frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl, 
            // Sign the back image URL
            backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl 
        })));
        
        collection.variations = signedVariations;
        // -----------------------

        res.status(200).json(collection);
    } catch (error) {
        console.error('Error fetching wear collection:', error);
        res.status(500).json({ message: 'Server error fetching collection.' });
    }
});
// ------------------------------------------------------------------------------------------------
// 2. MODIFIED ROUTE: POST /api/admin/wearscollections (Create New Collection) 
// UPDATED: Handles front-view and back-view file uploads for each variation.
// ------------------------------------------------------------------------------------------------

// Define the expected file fields dynamically (e.g., front-view-upload-1, back-view-upload-1, up to index 4)
const uploadFields = Array.from({ length: 4 }, (_, i) => [
    { name: `front-view-upload-${i + 1}`, maxCount: 1 },
    { name: `back-view-upload-${i + 1}`, maxCount: 1 }
]).flat();

app.post(
    '/api/admin/wearscollections',
    verifyToken, 
    upload.fields(uploadFields), 
    async (req, res) => {
        try {
            // --- A. Extract JSON Metadata ---
            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload." });
            }
            const collectionData = JSON.parse(req.body.collectionData);

            // --- B. Process Files and Integrate Paths into Variations ---
            const files = req.files; 
            const finalVariations = [];
            const uploadPromises = [];
            
            // Loop through the variations metadata from the client
            for (const variation of collectionData.variations) {
                const index = variation.variationIndex;
                const frontFileKey = `front-view-upload-${index}`;
                const backFileKey = `back-view-upload-${index}`;
                
                const frontFileArray = files[frontFileKey];
                const backFileArray = files[backFileKey];

                const frontFile = frontFileArray && frontFileArray[0];
                const backFile = backFileArray && backFileArray[0];

                if (!frontFile || !backFile) {
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                // Wait for both files for this variation to upload
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            frontImageUrl: frontImageUrl, // Store the permanent, private URL
                            backImageUrl: backImageUrl,   // Store the permanent, private URL
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            // Wait for all Backblaze B2 uploads to complete
            await Promise.all(uploadPromises);

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
            }

            // --- C. Create the Final Collection Object ---
            const newCollection = new WearsCollection({
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price, 
                sizes: collectionData.sizes,
                totalStock: collectionData.totalStock,
                isActive: collectionData.isActive, // Use the client's explicit isActive status
                variations: finalVariations, 
            });

            // --- D. Save to Database ---
            const savedCollection = await newCollection.save();

            // Success Response
            res.status(201).json({ 
                message: 'Wears Collection created and images uploaded successfully to Backblaze B2.',
                collectionId: savedCollection._id,
                name: savedCollection.name
            });

        } catch (error) {
            console.error('Error creating wear collection:', error); 
            // Handle Mongoose validation errors
            if (error.name === 'ValidationError') {
                // Better validation message extraction for client
                const messages = Object.values(error.errors).map(err => err.message).join(', ');
                return res.status(400).json({ message: `Validation Error: ${messages}`, errors: error.errors }); 
            }
            // Generic error
            res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
        }
    }
);

// ------------------------------------------------------------------------------------------------
// 3. MODIFIED ROUTE: PUT /api/admin/wearscollections/:id (Update Collection)
// UPDATED: Removed stock validation in quick restock to allow 'isActive: true' with 'totalStock: 0'.
// ------------------------------------------------------------------------------------------------
app.put(
    '/api/admin/wearscollections/:id',
    verifyToken, 
    upload.fields(uploadFields), // Use the updated dual-image field names
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await WearsCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Collection not found for update.' });
            }

            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            
            // --- A. HANDLE QUICK RESTOCK (Simple JSON Body, No Files/collectionData wrapper) ---
            if (isQuickRestock && !req.body.collectionData) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }
                
                // --- MODIFICATION START ---
                // We are removing the validation that required totalStock > 0 to set isActive: true.
                // This allows the admin to keep an item active (visible) even with 0 stock, 
                // enabling the frontend to display the "Out of Stock" label.
                
                // Original commented out validation:
                // if (isActive === true && totalStock <= 0) {
                //      return res.status(400).json({ message: "Total stock must be greater than zero to activate/restock." });
                // }
                // --- MODIFICATION END ---

                // Perform simple update
                existingCollection.totalStock = totalStock;
                existingCollection.isActive = isActive; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Collection quick-updated. Stock: ${updatedCollection.totalStock}, Active: ${updatedCollection.isActive}.`,
                    collectionId: updatedCollection._id
                });
            }

            // --- B. HANDLE FULL FORM SUBMISSION (multipart/form-data with collectionData JSON and optional Files) ---

            if (!req.body.collectionData) {
                return res.status(400).json({ message: "Missing collection data payload for full update." });
            }

            const collectionData = JSON.parse(req.body.collectionData);
            const files = req.files; 
            const updatedVariations = [];
            const uploadPromises = [];
            const oldImagesToDelete = [];

            // Iterate through the variations submitted from the frontend (collectionData)
            for (const incomingVariation of collectionData.variations) {
                const index = incomingVariation.variationIndex;
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === index);

                // Initialize with existing permanent URLs from DB
                let finalFrontUrl = existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = existingPermanentVariation?.backImageUrl || null;

                // --- Process FRONT Image ---
                const frontFileKey = `front-view-upload-${index}`;
                const frontFileArray = files[frontFileKey];
                const newFrontFile = frontFileArray && frontFileArray[0];

                if (newFrontFile) {
                    // New file uploaded: Schedule upload and mark old URL for deletion
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => {
                        finalFrontUrl = url;
                    });
                    uploadPromises.push(frontUploadPromise);
                } else if (!finalFrontUrl) {
                    // Critical: No new file, and no existing URL (shouldn't happen on update if created correctly)
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }
                
                // --- Process BACK Image ---
                const backFileKey = `back-view-upload-${index}`;
                const backFileArray = files[backFileKey];
                const newBackFile = backFileArray && backFileArray[0];

                if (newBackFile) {
                    // New file uploaded: Schedule upload and mark old URL for deletion
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => {
                        finalBackUrl = url;
                    });
                    uploadPromises.push(backUploadPromise);
                } else if (!finalBackUrl) {
                    // Critical: No new file, and no existing URL
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }
                
                // After upload promises resolve (in Promise.all below), the `final*Url` variables will hold the correct values.
                // For now, prepare the structure to be built after waiting for uploads.
                updatedVariations.push({
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    // Use the permanent URLs (either existing or new after upload)
                    get frontImageUrl() { return finalFrontUrl; }, 
                    get backImageUrl() { return finalBackUrl; }, 
                });
            }
            
            // Wait for all Backblaze B2 uploads to complete.
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // --- Update the Document Fields ---
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            existingCollection.sizes = collectionData.sizes;
            existingCollection.totalStock = collectionData.totalStock;
            existingCollection.isActive = collectionData.isActive;
            
            // Map final variations without the getters before saving
            existingCollection.variations = updatedVariations.map(v => ({
                variationIndex: v.variationIndex,
                colorHex: v.colorHex,
                frontImageUrl: v.frontImageUrl, 
                backImageUrl: v.backImageUrl, 
            }));
            
            // --- Save to Database ---
            const updatedCollection = await existingCollection.save();

            // --- Delete old images in the background (fire and forget) ---
            oldImagesToDelete.forEach(url => deleteFileFromPermanentStorage(url));

            // Success Response
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

// ------------------------------------------------------------------------------------------------
// 4. MODIFIED ROUTE: DELETE /api/admin/wearscollections/:id (Delete Collection) 
// UPDATED: Deletes both frontImageUrl and backImageUrl.
// ------------------------------------------------------------------------------------------------
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

// ------------------------------------------------------------------------------------------------
// 5. MODIFIED ROUTE: GET /api/admin/wearscollections (Fetch All Collections) 
// UPDATED: Signs both frontImageUrl and backImageUrl for each variation in the list.
// ------------------------------------------------------------------------------------------------
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

            // --- SIGN URLS FOR ALL COLLECTIONS HERE ---
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    // Sign both image URLs
                    frontImageUrl: await generateSignedUrl(v.frontImageUrl) || v.frontImageUrl,
                    backImageUrl: await generateSignedUrl(v.backImageUrl) || v.backImageUrl
                })));
                return {
                    ...collection,
                    variations: signedVariations
                };
            }));
            // ------------------------------------------

            // Send the list of signed collections as a JSON array
            res.status(200).json(signedCollections);
        } catch (error) {
            console.error('Error fetching wear collections:', error);
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);
// ------------------------------------------------------------------------------------------------
// MODIFIED PUBLIC ROUTE: GET /api/collections/wears (For Homepage Display)
// Fetches active collections, signs BOTH front and back image URLs, and sends simplified data.
// ------------------------------------------------------------------------------------------------
app.get('/api/collections/wears', async (req, res) => {
    try {
        // 1. Fetch only ACTIVE collections. Remove the check for totalStock > 0
        // to allow out-of-stock items to be sent to the frontend for display.
        const collections = await WearsCollection.find({ isActive: true }) // <-- MODIFIED QUERY
            .select('_id name tag price variations sizes totalStock') 
            .sort({ createdAt: -1 })
            .lean(); 

        // 2. Prepare the data for the public frontend
        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            // Map Mongoose variation to a simpler public variant object
            const variants = await Promise.all(collection.variations.map(async (v) => ({
                color: v.colorHex,
                
                // CRITICAL UPDATE: Sign the permanent URL for the front view
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Front+View+Error',
                
                // CRITICAL UPDATE: Sign the permanent URL for the back view
                backImageUrl: await generateSignedUrl(v.backImageUrl) || 'https://placehold.co/400x400/111111/FFFFFF?text=Back+View+Error'
            })));

            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                availableSizes: collection.sizes,
                // The totalStock field is now passed to the frontend to check if it's 0
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

// --- NETLIFY EXPORTS for api.js wrapper ---
module.exports = {
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};