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
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner'); // NEW IMPORT

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
        // We use BLAZE_BUCKET_NAME to robustly find the start of the key path.
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
        // This temporary URL allows the frontend to access the private file.
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


// --- MONGODB SCHEMAS & MODELS (Unchanged) ---
const adminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, default: 'admin' }
});
const Admin = mongoose.models.Admin || mongoose.model('Admin', adminSchema);

const ProductVariationSchema = new mongoose.Schema({
    variationIndex: { type: Number, required: true, min: 1, max: 4 },
    imageUrl: { type: String, required: true }, // Stores the permanent, private B2 URL
    colorHex: { type: String, required: true, match: /^#([0-9A-F]{3}){1,2}$/i }
}, { _id: false });

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

WearsCollectionSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
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

// ------------------------------------------------------------------------------------------------
// MODIFIED ROUTE: GET /api/admin/wearscollections/:id (Fetch Single Collection)
// Signs private image URLs before sending to client.
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
            imageUrl: await generateSignedUrl(v.imageUrl) || v.imageUrl // Replace with signed URL or keep original on failure
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
// ROUTE: POST /api/admin/wearscollections (Create New Collection) - Unchanged Logic
// ------------------------------------------------------------------------------------------------

app.post(
    '/api/admin/wearscollections',
    verifyToken, 
    upload.fields(Array.from({ length: 4 }, (_, i) => ({ name: `image-${i + 1}`, maxCount: 1 }))), 
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
                const fileKey = `image-${variation.variationIndex}`;
                const uploadedFileArray = files[fileKey];

                if (uploadedFileArray && uploadedFileArray[0]) {
                    const uploadedFile = uploadedFileArray[0];

                    // 1. Upload the file to Backblaze B2 (stores the permanent private URL)
                    const uploadPromise = uploadFileToPermanentStorage(uploadedFile).then(imageUrl => {
                        // 2. Create the final variation object
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            imageUrl: imageUrl, // Store the permanent, private URL
                        });
                    });
                    uploadPromises.push(uploadPromise);
                } else {
                    // This handles cases where a file is required but not present during creation.
                    // The client side should generally prevent this, but this is a final safety net.
                    console.warn(`File missing for variation index ${variation.variationIndex}`);
                    if (!files || !files[fileKey]) {
                         throw new Error(`Missing image for Variation #${variation.variationIndex}.`);
                    }
                }
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
                sizes: collectionData.sizes,
                totalStock: collectionData.totalStock,
                variations: finalVariations, 
            });
            // Set isActive based on totalStock for creation
            newCollection.isActive = collectionData.totalStock > 0;


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
                return res.status(400).json({ message: error.message, errors: error.errors }); 
            }
            // Generic error
            res.status(500).json({ message: 'Server error during collection creation or file upload.', details: error.message });
        }
    }
);

// ------------------------------------------------------------------------------------------------
// 🌟 MODIFIED ROUTE: PUT /api/admin/wearscollections/:id (Handle Full Form Update OR Quick Restock JSON)
// ------------------------------------------------------------------------------------------------

app.put(
    '/api/admin/wearscollections/:id',
    verifyToken, 
    // Use optional file parsing. If no files are sent, req.files will be {}
    upload.fields(Array.from({ length: 4 }, (_, i) => ({ name: `image-${i + 1}`, maxCount: 1 }))), 
    async (req, res) => {
        const collectionId = req.params.id;
        let existingCollection;
        
        try {
            existingCollection = await WearsCollection.findById(collectionId);
            if (!existingCollection) {
                return res.status(404).json({ message: 'Collection not found for update.' });
            }

            // Check if the request is a simple JSON update (Quick Restock) or a full form update (multipart/form-data).
            const isQuickRestock = req.get('Content-Type')?.includes('application/json');
            const hasFiles = req.files && Object.keys(req.files).length > 0;
            
            // --- A. HANDLE QUICK RESTOCK (Simple JSON Body, No Files/collectionData wrapper) ---
            if (isQuickRestock && !hasFiles && !req.body.collectionData) {
                const { totalStock, isActive } = req.body;

                if (totalStock === undefined || isActive === undefined) {
                    return res.status(400).json({ message: "Missing 'totalStock' or 'isActive' in simple update payload." });
                }

                if (totalStock <= 0) {
                     return res.status(400).json({ message: "Total stock must be greater than zero for Quick Restock/Activate." });
                }
                
                // Perform simple update
                existingCollection.totalStock = totalStock;
                // Force active state if stock is > 0, as per the quick restock requirement
                existingCollection.isActive = true; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Collection quick-restocked to ${updatedCollection.totalStock} and activated.`,
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
                const fileKey = `image-${incomingVariation.variationIndex}`;
                const uploadedFileArray = files[fileKey];
                
                // Find the existing permanent URL for this variation (using the permanent URL stored in DB)
                const existingPermanentVariation = existingCollection.variations.find(v => v.variationIndex === incomingVariation.variationIndex);
                
                let newImageUrl = existingPermanentVariation?.imageUrl || null; // Start with the DB's permanent URL

                if (uploadedFileArray && uploadedFileArray[0]) {
                    // 1. New file uploaded: Schedule upload and mark old permanent URL for deletion
                    const uploadedFile = uploadedFileArray[0];
                    if (existingPermanentVariation && existingPermanentVariation.imageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.imageUrl);
                    }
                    
                    const uploadPromise = uploadFileToPermanentStorage(uploadedFile).then(imageUrl => {
                        newImageUrl = imageUrl;
                        updatedVariations.push({
                            variationIndex: incomingVariation.variationIndex,
                            colorHex: incomingVariation.colorHex,
                            imageUrl: newImageUrl, // Store the NEW permanent URL
                        });
                    });
                    uploadPromises.push(uploadPromise);
                } else {
                    // 2. No new file: Use the existing permanent URL found in the database (or the one passed if a new variation)
                    // NOTE: The incomingVariation.imageUrl from the client is the *Signed URL* if no file was uploaded. 
                    // We must rely on the existingPermanentVariation.imageUrl from the database if we are retaining the old image.
                    
                    // If this is a re-indexed variation, it might be an issue, but since the client now sends the Signed URL 
                    // in `incomingVariation.imageUrl`, and we know the DB stores the permanent one, we must use the DB's permanent URL 
                    // if it exists, or the incoming value if the variation is brand new (which shouldn't happen on update unless deleting others).
                    if (existingPermanentVariation && existingPermanentVariation.imageUrl) {
                         newImageUrl = existingPermanentVariation.imageUrl;
                    } else if (incomingVariation.imageUrl) {
                        // FALLBACK: If a variation was removed and re-added but we want to retain the image, the client 
                        // sends the signed URL. For simplicity, we assume if we are not uploading a file, we want to 
                        // keep the *original* image from the DB entry that matches the variation index. 
                        // If no match in DB, this is complex. Sticking to the safer logic:
                        // IF no new file AND existing variation exists -> use existing permanent URL
                        newImageUrl = existingPermanentVariation ? existingPermanentVariation.imageUrl : incomingVariation.imageUrl;
                    }
                    
                    if (newImageUrl) {
                         updatedVariations.push({
                             variationIndex: incomingVariation.variationIndex,
                             colorHex: incomingVariation.colorHex,
                             imageUrl: newImageUrl, 
                         });
                    }
                }
            }
            
            // Wait for all Backblaze B2 uploads to complete
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                 return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // --- Update the Document Fields ---
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.sizes = collectionData.sizes;
            existingCollection.totalStock = collectionData.totalStock;
            existingCollection.variations = updatedVariations;
            // Only update isActive if explicitly sent (otherwise it stays whatever the stock/manual value is)
            existingCollection.isActive = collectionData.isActive !== undefined ? collectionData.isActive : existingCollection.isActive;
            
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
                return res.status(400).json({ message: error.message, errors: error.errors }); 
            }
            res.status(500).json({ message: 'Server error during collection update or file upload.', details: error.message });
        }
    }
);

// ------------------------------------------------------------------------------------------------
// ROUTE: DELETE /api/admin/wearscollections/:id (Delete Collection) - Unchanged Logic
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
            deleteFileFromPermanentStorage(v.imageUrl);
        });

        res.status(200).json({ message: `Collection ${collectionId} and associated images deleted successfully.` });
    } catch (error) {
        console.error('Error deleting wear collection:', error);
        res.status(500).json({ message: 'Server error during collection deletion.' });
    }
});


// ------------------------------------------------------------------------------------------------
// MODIFIED ROUTE: GET /api/admin/wearscollections (Fetch All Collections)
// Signs private image URLs before sending to client.
// ------------------------------------------------------------------------------------------------
app.get(
    '/api/admin/wearscollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections, use .lean() for performance and modification
            const collections = await WearsCollection.find({})
                .select('_id name tag variations totalStock isActive')
                .sort({ createdAt: -1 })
                .lean(); 

            // --- SIGN URLS FOR ALL COLLECTIONS HERE ---
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
                    imageUrl: await generateSignedUrl(v.imageUrl) || v.imageUrl // Sign each image URL
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
            // Ensure server always returns JSON on errors
            res.status(500).json({ message: 'Server error while fetching collections.', details: error.message });
        }
    }
);


// --- NETLIFY EXPORTS for api.js wrapper ---
module.exports = {
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};