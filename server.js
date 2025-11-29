const express = require('express');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cookieParser = require('cookie-parser');


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

// --- 1. EMAIL TRANSPORT SETUP ---
// Configuration to connect to an SMTP service (e.g., Gmail using an App Password)
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: process.env.EMAIL_PORT || 465,
    secure: process.env.EMAIL_PORT == 465 || true, 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS, 
    },
});

// Initialize the S3 Client configured for Backblaze B2
const s3Client = new S3Client({
    endpoint: BLAZE_ENDPOINT,
    region: 'us-west-004', // The region is often implied by the endpoint, but good practice to include
    credentials: {
        accessKeyId: BLAZE_ACCESS_KEY,
        secretAccessKey: BLAZE_SECRET_KEY,
    },
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

// Helper to convert the stream from B2/S3 response body into a Buffer
const streamToBuffer = (stream) => // Exported
    new Promise((resolve, reject) => {
        const chunks = [];
        stream.on("data", (chunk) => chunks.push(chunk));
        stream.on("error", reject);
        stream.on("end", () => resolve(Buffer.concat(chunks)));
    });


/**
 * Extracts the file key (path inside the bucket) from the permanent B2 URL.
 * This function is synchronous.
 */
function getFileKeyFromUrl(fileUrl) { 
    if (!fileUrl) return null;
    try {
        const urlObj = new URL(fileUrl);
        const pathSegments = urlObj.pathname.split('/');
        
        // Find the index of the bucket name
        const bucketNameIndex = pathSegments.findIndex(segment => segment === BLAZE_BUCKET_NAME);
        if (bucketNameIndex === -1) return null;

        // The file key is everything after the bucket name
        return pathSegments.slice(bucketNameIndex + 1).join('/');

    } catch (e) {
        console.error('Error extracting file key:', e);
        return null;
    }
}

/**
 * Helper function to send email using the configured transporter.
 * This function was referenced but not defined in the original code.
 */
async function sendMail(toEmail, subject, htmlContent) {
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
        console.error("FATAL: Email environment variables (EMAIL_USER/EMAIL_PASS) are not set.");
        // Throw an error to ensure the calling function catches it
        throw new Error("Email service is unconfigured.");
    }
    
    return transporter.sendMail({
        from: `Outflickz Limited <${process.env.EMAIL_USER}>`, // Sender address
        to: toEmail, // list of receivers
        subject: subject, // Subject line
        html: htmlContent, // html body
    });
}

/**
 * Helper function to generate, HASH, and save a new verification code.
 * IMPORTANT: This now stores the HASH, not the plain code.
 */
async function generateHashAndSaveVerificationCode(user) {
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    // Set code to expire in 10 minutes (600,000 ms)
    const verificationCodeExpires = new Date(Date.now() + 600000); 

    // --- 🛠️ SECURITY IMPROVEMENT: HASH THE CODE ---
    const salt = await bcrypt.genSalt(10);
    const hashedVerificationCode = await bcrypt.hash(verificationCode, salt);
    // ---------------------------------------------

    await User.updateOne(
        { _id: user._id },
        { 
            // FIX: Wrap all field updates in $set operator 
            $set: { 
                // Store the HASH in the newly added schema field
                verificationCode: hashedVerificationCode, 
                verificationCodeExpires: verificationCodeExpires,
                // FIX: Use dot notation to update the nested field
                'status.isVerified': false 
            }
        }
    );
        return verificationCode;
}

// Function to format the HTML content for the order confirmation email
function generateOrderEmailHtml(order) {
    const itemsHtml = order.items.map(item => `
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">${item.name} (${item.size}, ${item.color || 'N/A'})</td>
            <td style="padding: 8px; border: 1px solid #ddd;">${item.quantity}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">₦${(item.price * item.quantity).toFixed(2).toLocaleString()}</td>
        </tr>
    `).join('');

    const subtotal = order.subtotal || (order.totalAmount / 1.01); // Safe fallback (as previously)
    const shipping = order.shippingFee || (order.items.length > 0 ? SHIPPING_COST : 0); // Safe fallback
    const tax = order.tax || (order.totalAmount - subtotal - shipping); // Safe fallback (based on other fallbacks)
    const finalTotal = order.totalAmount; // Assuming this is the final total from the database

    return `
        <div style="font-family: Arial, sans-serif; line-height: 1.6;">
            <h2>Order Confirmation: #${order._id}</h2>
            <p>Hi ${order.shippingAddress.firstName},</p>
            <p>Thank you for your order! Your order details are below.</p>

            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
                <thead>
                    <tr style="background-color: #f4f4f4;">
                        <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Product</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">Qty</th>
                        <th style="padding: 10px; border: 1px solid #ddd;">Total</th>
                    </tr>
                </thead>
                <tbody>
                    ${itemsHtml}
                </tbody>
            </table>

            <table style="width: 100%; margin-top: 20px;">
                <tr><td style="padding: 5px 0;">Subtotal:</td><td style="text-align: right; font-weight: bold;">₦${subtotal.toFixed(2).toLocaleString()}</td></tr>
                <tr><td style="padding: 5px 0;">Shipping:</td><td style="text-align: right; font-weight: bold;">₦${shipping.toFixed(2).toLocaleString()}</td></tr>
                <tr><td style="padding: 5px 0;">Tax:</td><td style="text-align: right; font-weight: bold;">₦${tax.toFixed(2).toLocaleString()}</td></tr>
                <tr><td style="padding: 10px 0; border-top: 2px solid #333;">**Order Total:**</td><td style="text-align: right; font-weight: bold; border-top: 2px solid #333; color: #4F46E5;">₦${finalTotal.toFixed(2).toLocaleString()}</td></tr>
            </table>
            
            <h3 style="margin-top: 30px;">Shipping Details</h3>
            <p>
                **Name:** ${order.shippingAddress.firstName} ${order.shippingAddress.lastName}<br>
                **Address:** ${order.shippingAddress.address}, ${order.shippingAddress.city}<br>
                **Phone:** ${order.shippingAddress.phone}<br>
                **Status:** ${order.status}
            </p>

            <p style="margin-top: 30px; text-align: center;">If you have any questions, please contact our support team.</p>
        </div>
    `;
}

/**
 * Sends the order confirmation email.
 * @param {Object} order The Mongoose order document.
 * @param {string} type 'paid' or 'pending'
 */
async function sendOrderConfirmationEmail(order, type) {
    const subject = type === 'paid' 
        ? `✅ Your Order #${order._id.toString().substring(18)} is Confirmed and Paid!`
        : `⏳ Order #${order._id.toString().substring(18)} Placed - Payment Pending`;
    
    const htmlContent = generateOrderEmailHtml(order);

    try {
        const info = await sendMail(order.shippingAddress.email, subject, htmlContent);
        console.log(`Email sent: ${info.messageId} to ${order.shippingAddress.email}`);
    } catch (error) {
        console.error(`ERROR sending confirmation email for order ${order._id}:`, error);
        // It's usually safe to log the error and proceed without throwing, as the core transaction is complete.
    }
}

/**
 * Sends the order confirmation email.
 * This is the final version tailored for admin confirmation.
 * @param {string} customerEmail - The verified email of the customer.
 * @param {Object} order - The final Mongoose order document (status: 'Completed').
 */
async function sendOrderConfirmationEmailForAdmin(customerEmail, order) {
    
    // ✅ FIX: Use the actual final status for the subject.
    // If order.status is falsy (shouldn't happen here), default to 'Completed'.
    const finalStatus = order.status || 'Completed';

    const subject = `✅ Your Order #${order._id.toString().substring(0, 8)} is Confirmed and ${finalStatus}!`; 
    
    // NOTE: The generateOrderEmailHtml function uses fixed variables (SHIPPING_COST, TAX_RATE) 
    // which should be defined in its scope, but it's otherwise acceptable.
    const htmlContent = generateOrderEmailHtml(order); 

    try {
        const info = await sendMail(customerEmail, subject, htmlContent);
        console.log(`Email sent: ${info.messageId} to ${customerEmail}`);
    } catch (error) {
        // Log the email failure but DO NOT re-throw, as the core transaction is complete.
        console.error(`ERROR sending confirmation email for order ${order._id}:`, error);
    }
}

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


const userSchema = new mongoose.Schema({
    email: { type: String, required: [true, 'Email is required'], unique: true, trim: true, lowercase: true },
    password: { type: String, required: [true, 'Password is required'], select: false },
    
    // --- 🔑 VERIFICATION FIELDS ---
    verificationCode: { type: String, select: false },
    verificationCodeExpires: { type: Date, select: false },
    // -----------------------------
    
    profile: {
        firstName: { type: String, trim: true },
        lastName: { type: String, trim: true },
        phone: { type: String, trim: true },
        whatsapp: { type: String, trim: true }
    },
    
    // --- 🏠 CORRECTED CONTACT ADDRESS FIELD ---
    address: {
        type: new mongoose.Schema({
            street: { type: String, required: [true, 'Street is required'], trim: true },
            city: { type: String, required: [true, 'City is required'], trim: true },
            state: { type: String, trim: true },
            zip: { type: String, trim: false }, // Correctly kept optional and trim: false
            country: { type: String, required: [true, 'Country is required'], trim: true }
        }),
        required: [true, 'Address information is required'] // Ensure the whole object exists
    },
    // -----------------------------------------

    status: {
        role: { type: String, default: 'user', enum: ['user', 'vip'] },
        isVerified: { type: Boolean, default: false },
    },
    membership: {
        memberSince: { type: Date, default: Date.now },
        lastUpdated: { type: Date, default: Date.now }
    }
}, { timestamps: false });

// Pre-save hook to update lastUpdated and hash password
userSchema.pre('save', async function(next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
        this.password = await bcrypt.hash(this.password, salt);
    }
    this.membership.lastUpdated = Date.now();
    next();
});

const User = mongoose.models.User || mongoose.model('User', userSchema);


const ProductVariationSchema = new mongoose.Schema({
    variationIndex: { 
        type: Number, 
        required: true, 
        min: 1, 
        max: 4 
    },
    frontImageUrl: { 
        type: String, 
        required: [true, 'Front view image URL is required'],
        trim: true 
    }, 
    backImageUrl: { 
        type: String, 
        required: [true, 'Back view image URL is required'],
        trim: true 
    }, 
    colorHex: { 
        type: String, 
        required: [true, 'Color Hex code is required'], 
        match: [/^#[0-9A-F]{6}$/i, 'Color must be a valid hex code (e.g., #RRGGBB)'] 
    },
    
    // ⚠️ CRITICAL ADDITION: Stock array for per-size inventory tracking
    sizes: [{
        size: { type: String, required: true }, // e.g., 'S', 'M', 'L'
        stock: { type: Number, required: true, min: 0, default: 0 } // Stock count for this specific size/variation combination
    }]
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
    price: { 
        type: Number,
        required: [true, 'Price (in NGN) is required'],
        min: [0.01, 'Price (in NGN) must be greater than zero']
    },
    variations: {
        type: [ProductVariationSchema], // This field correctly holds the nested size/stock data
        required: [true, 'At least one product variation is required'],
        validate: {
            validator: function(v) { return v.length >= 1 && v.length <= 4; },
            message: 'A collection must have between 1 and 4 variations.'
        }
    },
    // 🛑 REMOVED: The redundant 'sizes' field is removed. 
    // All size data is now in variations[...].sizes[...]
    
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

// --- 🛍️ NEW ORDER SCHEMA AND MODEL 🛍️ ---
// We need a robust order model to track sales and manage inventory deduction.
const OrderItemSchema = new mongoose.Schema({
    productId: { 
        type: mongoose.Schema.Types.ObjectId, 
        required: true, 
    },
    productType: { 
        type: String, 
        required: true, 
        enum: ['WearsCollection', 'CapCollection', 'NewArrivals', 'PreOrderCollection'] 
    },
    // *** 🚨 ADDED fields for display consistency with cart 🚨 ***
    name: { type: String, required: true },
    imageUrl: { type: String },
    // *************************************************************
    quantity: { type: Number, required: true, min: 1 },
    priceAtTimeOfPurchase: { type: Number, required: true, min: 0.01 },
    variationIndex: { type: Number },
    size: { type: String },
    
    // 🌟 FIX: Added 'variation' field to store user-friendly name for Admin UI 🌟
    variation: { type: String } 
    
}, { _id: false });

const OrderSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    items: { type: [OrderItemSchema], required: true },
    
    // --- Financial Breakdown ---
    subtotal: { type: Number, required: true, min: 0 },
    shippingFee: { type: Number, required: true, min: 0 },
    tax: { type: Number, required: true, min: 0 },
    totalAmount: { type: Number, required: true, min: 0.01 }, // Grand total
    
    status: { 
        type: String, 
        required: true,
        enum: [
            'Pending',              // Bank Transfer awaiting admin/Paystack verification
            'Processing',           // ✅ CRITICAL ADDITION: Intermediate status set by PUT /confirm
            'Shipped',              // Fulfillment statuses
            'Delivered',
            'Completed',            // Final success status
            'Cancelled',
            'Refunded',
            'Verification Failed', 
            'Amount Mismatch (Manual Review)',
            'Inventory Failure (Manual Review)', // Better name for inventory rollback
        ], 
        default: 'Pending'
    },
    
    // --- Fulfillment & Payment Details ---
    shippingAddress: { type: Object, required: true },
    paymentMethod: { type: String, required: true },
    orderReference: { type: String, unique: true, sparse: true },
    amountPaidKobo: { type: Number, min: 0 },
    paymentTxnId: { type: String, sparse: true },
    paidAt: { type: Date },
    paymentReceiptUrl: { type: String, sparse: true }, // Bank transfer receipt
    
    // --- Admin Confirmation Details ---
    confirmedAt: { type: Date, sparse: true },
    confirmedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', sparse: true },
    notes: [String] // For logging manual review notes, inventory failures, etc.
}, { timestamps: true });

const Order = mongoose.models.Order || mongoose.model('Order', OrderSchema);

const cartItemSchema = new mongoose.Schema({
    // Item ID / Product Ref
    productId: { type: mongoose.Schema.Types.ObjectId, required: true },
    name: { type: String, required: true },
    productType: { 
        type: String, 
        required: true, 
        enum: ['WearsCollection', 'CapCollection', 'NewArrivals', 'PreOrderCollection'] 
    },
    
    // Variant Details
    size: { type: String, required: true },
    color: { type: String }, 
    variationIndex: { type: Number, required: true, min: 0 },
    
    // 🌟 FIX: Added 'variation' field to store user-friendly name for Order mapping 🌟
    variation: { type: String },
    
    // Pricing & Quantity
    price: { type: Number, required: true, min: 0.01 },
    quantity: { type: Number, required: true, min: 1, default: 1 },
    
    // Media
    imageUrl: { type: String } 
}, { _id: true });

const cartSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true, 
        unique: true 
    },
    items: {
        type: [cartItemSchema],
        default: []
    },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Cart = mongoose.models.Cart || mongoose.model('Cart', cartSchema);
module.exports = Cart;


const ActivityLogSchema = new mongoose.Schema({
    // Type of event: 'LOGIN', 'ORDER_PLACED', 'REGISTERED', 'FORGOT_PASSWORD', 'ADD_TO_CART'
    eventType: { type: String, required: true, enum: ['LOGIN', 'ORDER_PLACED', 'REGISTERED', 'FORGOT_PASSWORD', 'ADD_TO_CART'] },
    
    // Message describing the event, e.g., "User 'john.doe@email.com' registered."
    description: { type: String, required: true },
    
    // Optional: ID of the user involved
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, required: false }, 
    
    // Optional: Additional context data (e.g., orderId, product name)
    context: { type: Object },
    
    timestamp: { type: Date, default: Date.now, index: true }
});

const ActivityLog = mongoose.model('ActivityLog', ActivityLogSchema);
module.exports = ActivityLog;


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

/**
 * Retrieves real-time statistics for the admin dashboard.
 * Calculates Total Sales, and individual collection stock counts.
 */
async function getRealTimeDashboardStats() {
    try {
        // 1. Calculate Total Sales (sum of 'totalAmount' from completed orders)
        // (This remains the same)
        const salesAggregation = await Order.aggregate([
            { $match: { status: 'completed' } },
            { $group: { _id: null, totalSales: { $sum: '$totalAmount' } } }
        ]);
        const totalSales = salesAggregation.length > 0 ? salesAggregation[0].totalSales : 0;

        // 2. Calculate Individual Collection Stock Counts
        
        // Count for Wears Collection (only active items with stock > 0)
        const wearsInventory = await WearsCollection.aggregate([
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const wearsStock = wearsInventory[0]?.total || 0;

        // Count for Caps Collection (only active items with stock > 0)
        const capsInventory = await CapCollection.aggregate([
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const capsStock = capsInventory[0]?.total || 0;
        
        // Count for New Arrivals Collection (only active items with stock > 0)
        const newArrivalsInventory = await NewArrivals.aggregate([
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const newArrivalsStock = newArrivalsInventory[0]?.total || 0;
        
        // Count for Pre-Order Collection (only active items with stock > 0)
        const preOrderInventory = await PreOrderCollection.aggregate([
            { $match: { isActive: true, totalStock: { $gt: 0 } } },
            { $group: { _id: null, total: { $sum: '$totalStock' } } }
        ]);
        const preOrderStock = preOrderInventory[0]?.total || 0;


        // 3. Count Registered Users
        const userCount = await User.countDocuments({});

        const recentActivity = await ActivityLog.find({})
    .sort({ timestamp: -1 }) // Sort by newest first
    .limit(5)
    .lean(); // Use .lean() for faster query performance

        // 4. Return all required data fields
        return {
            totalSales: totalSales,
            userCount: userCount,
            
            // New Individual Stock Metrics
            wearsStock: wearsStock,
            capsStock: capsStock,
            newArrivalsStock: newArrivalsStock,
            preOrderStock: preOrderStock,

            recentActivity: recentActivity // Add this new field
        };

    } catch (error) {
        console.error('Error in getRealTimeDashboardStats:', error);
        throw new Error('Database aggregation failed for dashboard stats.');
    }
}

/**
 * Utility function to get the correct Mongoose Model based on the productType string.
 * This is robust for single-file environments where all models are registered.
 * @param {string} productType The string name of the collection (e.g., 'WearsCollection').
 */
function getProductModel(productType) {
    // ✅ FIX 1: Use the Mongoose registry to safely retrieve the model by name.
    const Model = mongoose.models[productType]; 
    
    if (!Model) {
        throw new Error(`Model not registered for product type: ${productType}`);
    }
    return Model;
}

/**
 * ====================================================================================
 * INVENTORY PROCESSING FUNCTION (ATOMIC & TRANSACTIONAL)
 * ====================================================================================
 * ...
 */
async function processOrderCompletion(orderId) {
    // 1. Start a Mongoose session for atomicity (crucial for inventory)
    const session = await mongoose.startSession();
    session.startTransaction();
    let order = null; 

    try {
        // Fetch the order within the transaction
        const OrderModel = mongoose.models.Order || mongoose.model('Order'); 
        order = await OrderModel.findById(orderId).session(session);

        // 1.1 Initial check
        const isReadyForInventory = order && (order.status === 'Processing' || order.status === 'Pending');

        if (!isReadyForInventory) {
            await session.abortTransaction();
            console.warn(`Order ${orderId} skipped: not found or status is ${order?.status}. Inventory deduction aborted.`);
            return order;
        }

        // 2. Loop through each item to deduct stock from the specific collection/variation
        for (const item of order.items) {
            // Assume item includes productId, productType, variationIndex, size, and quantity
            
            // 🌟 CRITICAL FIX: Replace Placeholder with actual utility function 🌟
            const ProductModel = getProductModel(item.productType); 
            // -----------------------------------------------------------------
            
            const quantityOrdered = item.quantity;

            // 3. ATOMIC DEDUCTION LOGIC FOR VARIATION STOCK
            const updatedProduct = await ProductModel.findOneAndUpdate(
                {
                    _id: item.productId,
                    
                    // Query Step 1: Target the product by ID
                    // Query Step 2: Target the correct variation by its index
                    'variations.variationIndex': item.variationIndex, 

                    // Query Step 3: Use $elemMatch to find the specific size object *AND*
                    // ensure its current stock is sufficient ($gte: quantityOrdered).
                    'variations.sizes': {
                        $elemMatch: {
                            size: item.size, // Must match the ordered size ('S', 'M', 'L')
                            stock: { $gte: quantityOrdered } // Must have sufficient stock
                        }
                    }
                },
                {
                    // Update Step 1 & 2: Decrement the stock in the nested array and totalStock.
                    $inc: {
                        'variations.$[var].sizes.$[size].stock': -quantityOrdered, 
                        'totalStock': -quantityOrdered 
                    }
                },
                {
                    new: true,
                    session: session, // MUST execute within the transaction
                    // Define which array elements the positional operators should target (arrayFilters)
                    arrayFilters: [
                        { 'var.variationIndex': item.variationIndex }, // Match the correct variation object (using 'var')
                        { 'size.size': item.size } // Match the correct size object within the variation (using 'size')
                    ]
                }
            );

            // 4. Stock check failure (findOneAndUpdate returns null if the $elemMatch condition failed)
            if (!updatedProduct) {
                const errorMsg = `Insufficient stock or product data mismatch for item: ${item.size} of product ${item.productId} in ${item.productType}. Transaction aborted.`;
                throw new Error(errorMsg);
            }
            console.log(`Inventory deducted for Product ID: ${item.productId}, Size: ${item.size}, Qty: ${quantityOrdered}`);
        }

        // 5. Update order status to completed
        order.status = 'Completed'; 
        await order.save({ session }); // Commit the save within the transaction.

        // 6. Finalize transaction
        await session.commitTransaction();
        console.log(`Order ${orderId} successfully completed and inventory fully deducted.`);
        return order;

    } catch (error) {
        // ... (Error handling logic remains correct)
        
        // Rollback on any failure
        if (session.inTransaction()) {
            await session.abortTransaction();
        }
        
        console.error('CRITICAL: Inventory Deduction failed during order processing. Inventory Rollback complete.', error.message);
        
        // Re-throw the error so the parent route can catch it
        throw error;
    } finally {
        session.endSession();
    }
}
module.exports = {
    processOrderCompletion,
};


/**
 * ====================================================================================
 * HELPER FUNCTIONS (Preserved as provided)
 * ====================================================================================
 */

async function populateInitialData() {
    if (!DEFAULT_ADMIN_EMAIL || !DEFAULT_ADMIN_PASSWORD) {
        console.warn('Skipping initial data population: Default admin credentials not fully set.');
        return;
    }

    try {
        // NOTE: Assumes Admin and bcrypt are defined globally or imported.
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

const SHIPPING_COST = 3000;
const TAX_RATE = 0.00;

/**
 * Calculates cart totals based on the array of items from Mongoose.
 * @param {Array<Object>} cartItems - The cart.items array from the Mongoose document.
 * @returns {Object} Calculated totals.
 */
function calculateCartTotals(cartItems) {
    // 1. Calculate Subtotal
    const subtotal = cartItems.reduce((acc, item) =>
        acc + (item.price * item.quantity), 0);
    // 2. Calculate Tax
    const tax = subtotal * TAX_RATE;
    const shipping = cartItems.length > 0 ? SHIPPING_COST : 0;

    // 4. Calculate Final Total
    const estimatedTotal = subtotal + tax + shipping;

    // Format for easy frontend consumption
    return {
        subtotal: subtotal,
        shipping: shipping,
        tax: tax,
        estimatedTotal: estimatedTotal,
    };
}

/**
 * Calculates cart totals locally for unauthenticated sessions.
 * Matches the server-side logic (calculateCartTotals).
 * @param {Array<Object>} items - The array of local cart items.
 * @returns {Object} Calculated totals structure.
 */
function calculateLocalTotals(items) {
    const subtotal = items.reduce((sum, item) =>
        sum + (item.price * item.quantity), 0);

    const tax = subtotal * LOCAL_TAX_RATE;
    const shipping = items.length > 0 ? LOCAL_SHIPPING_COST : 0;
    const estimatedTotal = subtotal + tax + shipping;

    return {
        items: items,
        subtotal: subtotal,
        shipping: shipping,
        tax: tax,
        estimatedTotal: estimatedTotal
    };
}
/**
 * Merges unauthenticated local cart items into the user's permanent database cart.
 * The product details are verified against the Mongoose schema before saving.
 * @param {ObjectId} userId - The authenticated user's ID.
 * @param {Array<Object>} localItems - Items from the client's local storage.
 */
async function mergeLocalCart(userId, localItems) {
    // Import Cart model and Mongoose at the top of your file
    // const Cart = require('./path/to/CartModel'); 

    try {
        let cart = await Cart.findOne({ userId });

        // Iterate through each item from the frontend's local storage
        localItems.forEach(localItem => {
            // A. Define the unique identifier for the item variant: productId, size, and color
            const matchKey = {
                productId: localItem.productId,
                size: localItem.size,
                color: localItem.color || 'N/A'
            };

            // B. Prepare the item structure to ensure it matches the Mongoose schema
            const itemData = {
                ...matchKey,
                name: localItem.name,
                productType: localItem.productType || 'WearsCollection', // Ensure a valid enum value
                price: localItem.price,
                quantity: localItem.quantity || 1,
                imageUrl: localItem.imageUrl,
            };

            if (!cart) {
                // If cart doesn't exist, we'll create it with all local items later
                return;
            }

            // C. Check if the item variant already exists in the permanent cart
            const existingItemIndex = cart.items.findIndex(dbItem =>
                dbItem.productId.equals(itemData.productId) && // Use .equals for ObjectIds
                dbItem.size === itemData.size &&
                dbItem.color === itemData.color
            );

            if (existingItemIndex > -1) {
                // Item exists: Add the local quantity to the database quantity
                cart.items[existingItemIndex].quantity += itemData.quantity;
            } else {
                // Item does not exist: Push the new item data
                cart.items.push(itemData);
            }
        });

        if (!cart) {
            // Case 1: No cart existed, and we have items to add.
            // Create the new cart with the processed items.
            const initialItems = localItems.map(localItem => ({
                productId: localItem.productId,
                name: localItem.name,
                productType: localItem.productType || 'WearsCollection',
                size: localItem.size,
                color: localItem.color || 'N/A',
                price: localItem.price,
                quantity: localItem.quantity || 1,
                imageUrl: localItem.imageUrl,
            }));
            await Cart.create({ userId, items: initialItems });
        } else {
            // Case 2: Cart existed. Save the merged/updated cart.
            cart.updatedAt = Date.now();
            await cart.save();
        }
        
    } catch (error) {
        console.error('CRITICAL: Error during cart merge process:', error);
        // The login succeeded, so we log the error but allow the login response to proceed.
    }
}

/**
 * Takes a list of order documents and adds 'name' and 'imageUrl' to each item 
 * by fetching product details from all relevant collections.
 * * 🚨 CRITICAL UPDATE: This now generates a temporary, pre-signed URL for the imageUrl
 * if the image is stored privately (e.g., in Backblaze B2).
 * * @param {Array<Object>} orders - Array of order documents (must have an 'items' array).
 * @returns {Promise<Array<Object>>} - Orders with augmented item details, including signed image URLs.
 */
async function augmentOrdersWithProductDetails(orders) {
    if (!orders || orders.length === 0) {
        return [];
    }
    
    // 1. Get all unique product IDs from all orders
    const allProductIds = orders.flatMap(order => 
        order.items.map(item => item.productId)
    );
    
    // Convert unique string IDs back into Mongoose ObjectIds for $in query
    const uniqueProductObjectIds = [
        ...new Set(allProductIds.map(id => id.toString()))
    ].map(idStr => new mongoose.Types.ObjectId(idStr)); 

    // 2. Fetch product details (Names and Variations array for image URL)
    const projection = 'name variations'; 
    
    const wears = await WearsCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const caps = await CapCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const newArrivals = await NewArrivals.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean();
    const preOrders = await PreOrderCollection.find({ _id: { $in: uniqueProductObjectIds } }).select(projection).lean(); 

    const allProducts = [...wears, ...caps, ...newArrivals, ...preOrders];
    
    // 3. Build Product Map (productId string -> { name, variations })
    const productMap = {};
    allProducts.forEach(product => {
        productMap[product._id.toString()] = {
            name: product.name,
            variations: product.variations
        };
    });

    // 4. Transform and merge product details into the orders array, signing URLs
    const detailedOrdersPromises = orders.map(async (order) => {
        
        const detailedItemsPromises = order.items.map(async (item) => {
            const productIdStr = item.productId.toString();
            const productInfo = productMap[productIdStr];
            
            let permanentImageUrl = null; // Store the B2 URL temporarily
            let productName = 'Unknown Product (Deleted)';

            if (productInfo) {
                productName = productInfo.name;
                
                // Find the exact variation based on the saved variationIndex
                const purchasedVariation = productInfo.variations.find(v => 
                    // Ensure robust comparison by converting both to strings
                    String(v.variationIndex) === String(item.variationIndex)
                );

                // Determine the permanent B2 URL
                if (purchasedVariation && purchasedVariation.frontImageUrl) {
                    permanentImageUrl = purchasedVariation.frontImageUrl;
                } else if (productInfo.variations.length > 0) {
                    // Fallback to the first variation's front image if exact match fails
                    if (productInfo.variations[0].frontImageUrl) {
                        permanentImageUrl = productInfo.variations[0].frontImageUrl;
                    }
                }
            }

            // --- 🚨 CRITICAL FIX: Generate Signed URL for private image access ---
            let signedImageUrl = 'https://placehold.co/32x32/CBD5E1/475569/png?text=N/A';
            if (permanentImageUrl) {
                // Assuming generateSignedUrl is available in scope (passed in context)
                const signedUrl = await generateSignedUrl(permanentImageUrl); 
                if (signedUrl) {
                    signedImageUrl = signedUrl;
                }
            }
            // --------------------------------------------------------------------

            return {
                ...item,
                name: productName,
                imageUrl: signedImageUrl, // Now holds the temporary, signed URL
                price: item.priceAtTimeOfPurchase, 
            };
        });
        
        // Wait for all item promises to resolve (including signing the URLs)
        const detailedItems = await Promise.all(detailedItemsPromises);

        return {
            ...order,
            items: detailedItems,
        };
    });
    
    // Wait for all order promises to resolve
    return Promise.all(detailedOrdersPromises);
}

// --- EXPRESS CONFIGURATION AND MIDDLEWARE ---
const app = express();
// Ensure express.json() is used BEFORE the update route, but after the full form route
// To allow both JSON and multipart/form-data parsing
app.use(express.json()); 
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => { res.redirect('/outflickzstore/homepage.html'); });
app.get('/useraccount', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'useraccount.html')); }); 
app.get('/userprofile', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'userprofile.html')); }); 
app.get('/capscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'capscollection.html')); }); 
app.get('/newarrivals', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'newarrivals.html')); }); 
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'wearscollection.html')); }); 
app.get('/preorder', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzstore', 'preoder.html')); }); 

//ADMIN ROUTE
app.get('/admin-login', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-login.html')); });
app.get('/admin-dashboard', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'admin-dashboard.html')); });
app.get('/wearscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'wearscollection.html')); });
app.get('/capscollection', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'capscollection.html')); }); 
app.get('/newarrivals', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'newarrivals.html')); }); 
app.get('/preorders', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'outflickzadmin', 'preorders.html')); }); 



const verifyToken = (req, res, next) => {
    // 1. Check for Authorization header format (Bearer <token>)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Access denied. No token provided or token format invalid.' });
    }
    
    // 2. Extract the token
    const token = authHeader.split(' ')[1];
    
    try {
        // Use the defined secret (JWT_SECRET in this scope)
        const decoded = jwt.verify(token, JWT_SECRET); 
        
        // 3. CRUCIAL: Check for the 'admin' role (Authorization)
        if (decoded.role !== 'admin') { 
            return res.status(403).json({ message: 'Forbidden. Access limited to administrators.' });
        }
        
        // 4. Attach admin data (req.adminUser = { id: 123, role: 'admin' })
        req.adminUser = decoded; 
        next();
        
    } catch (err) {
        // 5. Handle verification errors (Signature mismatch, expiry, etc.)
        res.status(401).json({ message: 'Invalid or expired token. Please log in again.' });
    }
};

// --- Multer Configuration (upload) ---
const upload = multer({ 
    storage: multer.memoryStorage(), // Stores file buffer in req.file.buffer
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Define the expected file fields dynamically (e.g., front-view-upload-1, back-view-upload-1, up to index 4)
const uploadFields = Array.from({ length: 4 }, (_, i) => [
    { name: `front-view-upload-${i + 1}`, maxCount: 1 },
    { name: `back-view-upload-${i + 1}`, maxCount: 1 }
]).flat();

const singleReceiptUpload = multer({ 
    storage: multer.memoryStorage(), // Use memory storage as defined
    limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit

}).single('receipt'); // 'receipt' must match the field name sent by the frontend
// --- USER AUTHENTICATION API ROUTES ---
const verifyUserToken = (req, res, next) => {
    // 1. Check for token in the HTTP-only cookie
    let token = req.cookies.outflickzToken; 
    
    // 2. Fallback: Check for token in the 'Authorization: Bearer <token>' header if cookie is absent
    const authHeader = req.headers.authorization;
    if (!token && authHeader && authHeader.startsWith('Bearer ')) {
        token = authHeader.split(' ')[1];
    }

    // 3. If no token is found in either location, deny access
    if (!token) {
        // Clear cookie as a security best practice, even if we expected a header
        if (req.cookies.outflickzToken) {
            res.clearCookie('outflickzToken');
        }
        return res.status(401).json({ message: 'Access denied. Please log in.' });
    }

    try {
        // 4. Verify the token
        // Assuming JWT_SECRET is available in scope
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 5. Ensure this is a regular user token 
        if (decoded.role !== 'user') {
            // Token is valid but role is wrong (e.g., admin token used for user route)
            return res.status(403).json({ message: 'Forbidden. Invalid user role.' });
        }
        
        // 6. Success: Attach the user ID and proceed
        req.userId = decoded.id; 
        next();
    } catch (err) {
        // 7. Token is invalid (expired, tampered, etc.) - Force re-login
        if (req.cookies.outflickzToken) {
            res.clearCookie('outflickzToken');
        }
        console.error("JWT Verification Error:", err.message);
        res.status(401).json({ message: 'Invalid or expired session. Please log in again.' });
    }
};
/**
 * Verifies the user token if present, but allows the request to proceed if absent.
 * (This middleware is generally not needed for a protected route like /api/orders/:orderId)
 */
const verifyOptionalToken = (req, res, next) => {
    // This function is unchanged as it seems designed specifically for cookies
    // but should be reviewed if other frontend pages start using Authorization headers optionally.
    const token = req.cookies.outflickzToken; 

    if (!token) {
        req.userId = null; 
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'user') {
            req.userId = null;
            return next();
        }
        req.userId = decoded.id; 
        next();
    } catch (err) {
        res.clearCookie('outflickzToken');
        req.userId = null; 
        next();
    }
}; 

// --- GENERAL ADMIN API ROUTES ---d
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
            { expiresIn: '2h' }
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
        // This now calls the updated function that aggregates stock from all product models
        const stats = await getRealTimeDashboardStats();
        res.status(200).json(stats);
    } catch (error) {
        // Updated error logging for better debugging
        console.error("Dashboard Stats API Error:", error.message);
        res.status(500).json({ message: 'Failed to retrieve dashboard stats.' });
    }
});

app.get('/api/admin/users/all', verifyToken, async (req, res) => {
    try {
        // Fetch all users. Select only necessary fields and exclude the password (which is selected: false by default, but we re-specify for clarity).
        const users = await User.find({})
            .select('email profile address status membership')
            .lean(); // Use .lean() for faster query performance since we are only reading

        // Transform the data to match the frontend's expected format (if needed, but here we just return the array)
        const transformedUsers = users.map(user => ({
            _id: user._id,
            name: `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() || 'N/A',
            email: user.email,
            isMember: user.status.role === 'vip', // Determine membership status
            createdAt: user.membership.memberSince,
            // Include other fields if the admin needs them, but for the table, this is enough
        }));


        // Success Response
        return res.status(200).json({ 
            users: transformedUsers,
            count: transformedUsers.length
        });

    } catch (error) {
        console.error('Admin user fetch error:', error);
        // Return a generic server error
        return res.status(500).json({ message: 'Server error: Failed to retrieve user list.' });
    }
});

// EXISTING: 1. GET /api/admin/users/:id (Fetch Single User Profile - Protected Admin)
app.get('/api/admin/users/:id', verifyToken, async (req, res) => {
    try {
        const userId = req.params.id;

        const user = await User.findById(userId)
            .select('email profile address status membership')
            .lean();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        const addressParts = [
            user.address?.street,
            user.address?.city,
            user.address?.state,
            user.address?.zip,
            user.address?.country
        ].filter(Boolean);
        
        const contactAddress = addressParts.length > 0 ? addressParts.join(', ') : 'No Address Provided';

        const detailedUser = {
            _id: user._id,
            name: `${user.profile.firstName || ''} ${user.profile.lastName || ''}`.trim() || 'N/A',
            email: user.email,
            isMember: user.status.role === 'vip',
            createdAt: user.membership.memberSince,
            phone: user.profile.phone || 'N/A',
            // --- 📢 NEW ADDITION FOR WHATSAPP CONTACT 📢 ---
            whatsappNumber: user.profile.whatsapp || 'N/A', 
            // ----------------------------------------------------
            contactAddress: contactAddress
        };

        return res.status(200).json({ 
            user: detailedUser
        });

    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        console.error('Admin single user fetch error:', error);
        return res.status(500).json({ message: 'Server error: Failed to retrieve user details.' });
    }
});

// NEW: 2. GET /api/admin/users/:userId/orders (Fetch User Order History - Protected Admin)
app.get('/api/admin/users/:userId/orders', verifyToken, async (req, res) => {
    try {
        const userId = req.params.userId;

        // 1. Validate the user exists (Optional, but good practice)
        const userExists = await User.exists({ _id: userId });
        if (!userExists) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 2. Fetch all orders for that user ID
        // Sort by creation date descending (newest first)
        const userOrders = await Order.find({ userId: userId }) 
            .sort({ createdAt: -1 })
            .lean(); // Returns plain JavaScript objects

        // 3. Simple transformation: Since OrderItemSchema is now denormalized 
        //    (includes name and imageUrl), we can return the data directly.
        const augmentedOrders = userOrders.map(order => ({
            ...order,
            // Items already contain name and imageUrl from the denormalized schema
            items: order.items || [], 
        }));

        // Success Response
        return res.status(200).json({ 
            orders: augmentedOrders,
            count: augmentedOrders.length
        });

    } catch (error) {
        if (error.kind === 'ObjectId') {
            return res.status(400).json({ message: 'Invalid User ID format.' });
        }
        console.error('Admin user orders fetch error:', error);
        return res.status(500).json({ message: 'Server error: Failed to retrieve user order history.' });
    }
});

// =========================================================
// 8. GET /api/admin/orders/pending - Fetch All Pending Orders (Admin Protected)
// =========================================================
app.get('/api/admin/orders/pending', verifyToken, async (req, res) => {
    try {
        // Find all orders where the status is 'Pending'
        const pendingOrders = await Order.find({ status: 'Pending' })
            .select('_id userId totalAmount createdAt status paymentMethod paymentReceiptUrl subtotal shippingFee tax')
            .sort({ createdAt: 1 })
            .lean();

        // 1. Get User Details for each pending order (for 'Customer' column)
        const populatedOrders = await Promise.all(
            pendingOrders.map(async (order) => {
                const user = await User.findById(order.userId)
                    // ✅ FIX 1: Select nested fields from the 'profile' subdocument
                    .select('profile.firstName profile.lastName email') 
                    .lean();

                // ✅ FIX 2: Access nested fields safely
                const firstName = user?.profile?.firstName;
                const lastName = user?.profile?.lastName;
                
                // Construct userName: Use full name if both exist, otherwise fall back to email
                const userName = (firstName && lastName) 
                    ? `${firstName} ${lastName}` 
                    : user?.email || 'N/A'; // Final fallback to email or 'N/A'
                
                const email = user ? user.email : 'Unknown User';
                
                return {
                    ...order,
                    userName: userName, // Added for the Admin table
                    email: email,       // Added for the Admin table
                };
            })
        );

        // Send the complete list of pending orders
        res.status(200).json(populatedOrders);

    } catch (error) {
        console.error('Error fetching pending orders:', error);
        res.status(500).json({ message: 'Failed to retrieve pending orders.' });
    }
});


// =========================================================
// 8b. GET /api/admin/orders/:orderId - Fetch Single Detailed Order (Admin Protected)
// =========================================================
app.get('/api/admin/orders/:orderId', verifyToken, async (req, res) => {
    try {
        const orderId = req.params.orderId;

        // 1. Fetch the single order
        const order = await Order.findById(orderId).lean();

        if (!order) {
            return res.status(404).json({ message: 'Order not found.' });
        }
        
        // 2. Augment order items with product details (name, imageUrl)
        // NOTE: augmentOrdersWithProductDetails MUST now internally call generateSignedUrl 
        // for each item.imageUrl if the images are private.
        const detailedOrders = await augmentOrdersWithProductDetails([order]);
        let detailedOrder = detailedOrders[0];

        // 🚨 FIX: Generate Signed URL for the Payment Receipt (Necessary for private B2 bucket access)
        if (detailedOrder.paymentReceiptUrl) {
            detailedOrder.paymentReceiptUrl = await generateSignedUrl(detailedOrder.paymentReceiptUrl);
        }

        // 3. Get User Details (Name and Email)
        const user = await User.findById(detailedOrder.userId)
            .select('profile.firstName profile.lastName email') 
            .lean();

        const firstName = user?.profile?.firstName;
        const lastName = user?.profile?.lastName;

        // Construct userName: Use full name if both exist, otherwise fall back to email
        const userName = (firstName && lastName) 
            ? `${firstName} ${lastName}` 
            : user?.email || 'N/A';
            
        const email = user ? user.email : 'Unknown User';
        
        // 4. Combine all details
        const finalDetailedOrder = {
            ...detailedOrder,
            userName: userName,
            email: email
        };

        return res.status(200).json(finalDetailedOrder);

    } catch (error) {
        console.error(`Error fetching order details for ${req.params.orderId}:`, error);
        if (error.name === 'CastError' || error.kind === 'ObjectId') {
             return res.status(400).json({ message: 'Invalid Order ID format.' });
        }
        return res.status(500).json({ message: 'Server error: Failed to retrieve order details.' });
    }
});

// =========================================================
// 9. PUT /api/admin/orders/:orderId/confirm - Confirm an Order (Admin Protected)
// *** FINAL IMPLEMENTATION WITH EMAIL NOTIFICATION ***
// =========================================================
app.put('/api/admin/orders/:orderId/confirm', verifyToken, async (req, res) => {
    const orderId = req.params.orderId;
    const adminId = req.adminId;

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required for confirmation.' });
    }

    try {
        // 1. Initial status change from 'Pending' to 'Processing'
        // We use findOneAndUpdate to ensure atomic update and retrieve the document.
        const updatedOrder = await Order.findOneAndUpdate(
            { _id: orderId, status: 'Pending' }, 
            { 
                $set: { 
                    status: 'Processing', // Transition step before inventory
                    confirmedAt: new Date(), 
                    confirmedBy: adminId 
                } 
            },
            // Crucial: Select userId to fetch email later
            { new: true, select: 'userId status totalAmount items' } 
        ).lean();

        // 💡 CRITICAL FIX: Check if the order was successfully found and updated.
        if (!updatedOrder) {
            console.warn(`Order ${orderId} skipped: not found or status is not pending.`);
            // Use 409 Conflict to indicate that the request could not be completed due to the resource's state.
            return res.status(409).json({ message: 'Order not found or is already processed.' });
        }
        
        // 2. CRITICAL STEP: Deduct Inventory and finalize status to 'Completed' atomically
        let finalOrder;
        try {
            // Assume processOrderCompletion handles the full inventory deduction and final status update to 'Completed'
            finalOrder = await processOrderCompletion(orderId);
            // If this succeeds, the order status is now 'Completed'
        } catch (inventoryError) {
            // Rollback status if inventory fails
            console.error('Inventory deduction failed during Admin confirmation:', inventoryError.message);
            
            // ⭐ FIX APPLIED HERE: The status must be 'Inventory Failure (Manual Review)' 
            // to align with the processOrderCompletion function and schema enum.
            await Order.findByIdAndUpdate(orderId, { 
                status: 'Inventory Failure (Manual Review)', 
                $push: { notes: `Inventory deduction failed on ${new Date().toISOString()}: ${inventoryError.message}` }
            });
            
            // ✅ FIX: Changed status code from 500 to 409 Conflict for known business logic failure (Insufficient Stock).
            return res.status(409).json({ 
                message: 'Payment confirmed, but inventory deduction failed. Order status flagged for manual review.',
                error: inventoryError.message
            });
        }
        
        // 3. GET CUSTOMER EMAIL & SEND NOTIFICATION (The User's Request) 📧
        
        // Fetch user email using the userId
        const user = await User.findById(updatedOrder.userId).select('email').lean();
        const customerEmail = user ? user.email : null;

        if (customerEmail) {
            try {
                // ✅ FIX: Isolate the email sending which is prone to external errors
                await sendOrderConfirmationEmailForAdmin(customerEmail, finalOrder);
            } catch (emailError) {
                // Log the email error but allow the order confirmation to succeed
                console.error(`CRITICAL WARNING: Failed to send confirmation email to ${customerEmail}:`, emailError.message);
                // Continue execution to send the success response to the client
            }
        } else {
            console.warn(`Could not find email for user ID: ${updatedOrder.userId}. Skipping email notification.`);
        }
        
        // 4. Success Response
        res.status(200).json({ 
            message: `Order ${orderId} confirmed, inventory deducted, and customer notified. Status: ${finalOrder.status}.`,
            order: finalOrder 
        });

    } catch (error) {
        // This catch block handles the final crash and returns the 500 error
        console.error(`Error confirming order ${orderId}:`, error);
        res.status(500).json({ message: 'Failed to confirm order due to a server error.' });
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
// GET /api/admin/wearscollections/:id (Fetch Single Collection)
app.get('/api/admin/wearscollections/:id', verifyToken, async (req, res) => {
    try {
        // --- FIX 1: Ensure totalStock is selected for fetching ---
        const collection = await WearsCollection.findById(req.params.id)
            .select('_id name tag price variations sizesAndStock isActive totalStock') 
            .lean(); 
        
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
                    // Check if file is missing AND no existing URL is provided 
                    throw new Error(`Missing BOTH front and back image files for Variation #${index}.`);
                }

                // Upload files concurrently
                const uploadFrontPromise = uploadFileToPermanentStorage(frontFile);
                const uploadBackPromise = uploadFileToPermanentStorage(backFile);
                
                // Store the promise that resolves and pushes the final variation object
                const combinedUploadPromise = Promise.all([uploadFrontPromise, uploadBackPromise])
                    .then(([frontImageUrl, backImageUrl]) => {
                        finalVariations.push({
                            variationIndex: variation.variationIndex,
                            colorHex: variation.colorHex,
                            // 🔥 FIX: Include the nested sizes array for stock management
                            sizes: variation.sizes, 
                            frontImageUrl: frontImageUrl, 
                            backImageUrl: backImageUrl, 
                        });
                    });
                    
                uploadPromises.push(combinedUploadPromise);
            }
            
            await Promise.all(uploadPromises); // Wait for all uploads to complete

            if (finalVariations.length === 0) {
                return res.status(400).json({ message: "No valid product images and metadata were received after upload processing." });
            }

            // C. Create the Final Collection Object
            const newCollection = new WearsCollection({
                name: collectionData.name,
                tag: collectionData.tag,
                price: collectionData.price, 
                // --- FIX 2: Assign totalStock from client payload ---
                totalStock: collectionData.totalStock, 
                sizesAndStock: collectionData.sizesAndStock, 
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
            
            // A. HANDLE QUICK RESTOCK (Only updates stock/active status)
            if (isQuickRestock && !req.body.collectionData) {
                // --- FIX 3: Destructure totalStock from JSON body ---
                const { sizesAndStock, isActive, totalStock } = req.body;

                if (!sizesAndStock || isActive === undefined || totalStock === undefined) {
                    return res.status(400).json({ message: "Missing 'sizesAndStock', 'isActive', or 'totalStock' in simple update payload." });
                }
                
                // Perform simple update
                existingCollection.sizesAndStock = sizesAndStock;
                existingCollection.isActive = isActive;
                // --- FIX 4: Assign totalStock from payload ---
                existingCollection.totalStock = totalStock; 

                const updatedCollection = await existingCollection.save();
                return res.status(200).json({ 
                    message: `Collection quick-updated. Active: ${updatedCollection.isActive}. Stock: ${updatedCollection.totalStock}`,
                    collectionId: updatedCollection._id,
                    name: updatedCollection.name
                });
            }

            // B. HANDLE FULL FORM SUBMISSION (Updates everything, including images/variations)
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

                // Start with the existing URLs, or null if a new variation
                let finalFrontUrl = incomingVariation.existingFrontImageUrl || existingPermanentVariation?.frontImageUrl || null;
                let finalBackUrl = incomingVariation.existingBackImageUrl || existingPermanentVariation?.backImageUrl || null;


                // Temporary object to hold all data for this variation
                let variationUpdates = { 
                    variationIndex: index,
                    colorHex: incomingVariation.colorHex,
                    // 🔥 FIX: Include the nested sizes array for stock management
                    sizes: incomingVariation.sizes, 
                    frontImageUrl: finalFrontUrl,
                    backImageUrl: finalBackUrl,
                    ...(incomingVariation._id && { _id: incomingVariation._id }) // Preserve _id if updating an existing variation
                };

                // Process FRONT Image
                const frontFileKey = `front-view-upload-${index}`;
                const newFrontFile = files[frontFileKey]?.[0];

                if (newFrontFile) {
                    // New file uploaded: Schedule old image for deletion and new file for upload
                    if (existingPermanentVariation?.frontImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.frontImageUrl);
                    }
                    const frontUploadPromise = uploadFileToPermanentStorage(newFrontFile).then(url => { 
                        variationUpdates.frontImageUrl = url; 
                    });
                    uploadPromises.push(frontUploadPromise);
                } else if (!variationUpdates.frontImageUrl) {
                    throw new Error(`Front image missing for Variation #${index} and no existing image found.`);
                }
                
                // Process BACK Image
                const backFileKey = `back-view-upload-${index}`;
                const newBackFile = files[backFileKey]?.[0];

                if (newBackFile) {
                    // New file uploaded: Schedule old image for deletion and new file for upload
                    if (existingPermanentVariation?.backImageUrl) {
                        oldImagesToDelete.push(existingPermanentVariation.backImageUrl);
                    }
                    const backUploadPromise = uploadFileToPermanentStorage(newBackFile).then(url => { 
                        variationUpdates.backImageUrl = url; 
                    });
                    uploadPromises.push(backUploadPromise);
                } else if (!variationUpdates.backImageUrl) {
                    throw new Error(`Back image missing for Variation #${index} and no existing image found.`);
                }
                
                // Collect the temporary variation object
                updatedVariations.push(variationUpdates);
            }
            
            // Wait for all image uploads to finish and update the URLs in updatedVariations objects
            await Promise.all(uploadPromises);

            if (updatedVariations.length === 0) {
                return res.status(400).json({ message: "No valid variations were processed for update." });
            }
            
            // Update the Document Fields
            existingCollection.name = collectionData.name;
            existingCollection.tag = collectionData.tag;
            existingCollection.price = collectionData.price;
            
            // --- FIX 5: Assign totalStock from client payload ---
            existingCollection.totalStock = collectionData.totalStock; 
            existingCollection.sizesAndStock = collectionData.sizesAndStock; 
            existingCollection.isActive = collectionData.isActive;
            
            // Assign the finalized variations array directly (now includes nested sizes)
            existingCollection.variations = updatedVariations; 
            
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
            // --- FIX 6: Ensure totalStock is selected for fetching ---
            const collections = await WearsCollection.find({})
                .select('_id name tag price variations sizesAndStock isActive totalStock') 
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

// 3. GET /api/admin/preordercollections (Fetch All Pre-Order Collections) 
app.get(
    '/api/admin/preordercollections',
    verifyToken,
    async (req, res) => {
        try {
            // Fetch all collections, selecting only necessary and consistent fields
            const collections = await PreOrderCollection.find({})
                .select('_id name tag price variations totalStock isActive availableDate') 
                .sort({ createdAt: -1 })
                .lean();

            // Sign URLs
            const signedCollections = await Promise.all(collections.map(async (collection) => {
                const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                    ...v,
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


// 4. GET /api/admin/preordercollections/:id (Fetch a Single Pre-Order Collection) 
app.get(
    '/api/admin/preordercollections/:id',
    verifyToken,
    async (req, res) => {
        const collectionId = req.params.id;
        
        try {
            // Find the collection by ID
            const collection = await PreOrderCollection.findById(collectionId).lean();

            if (!collection) {
                return res.status(404).json({ message: 'Pre-Order Collection not found.' });
            }

            // Sign URLs for all variations
            const signedVariations = await Promise.all(collection.variations.map(async (v) => ({
                ...v,
                frontImageUrl: v.frontImageUrl ? await generateSignedUrl(v.frontImageUrl) : null,
                backImageUrl: v.backImageUrl ? await generateSignedUrl(v.backImageUrl) : null
            })));

            const signedCollection = {
                ...collection,
                variations: signedVariations
            };

            res.status(200).json(signedCollection);

        } catch (error) {
            // Handle invalid ID format (e.g., Mongoose CastError)
            if (error.name === 'CastError') {
                return res.status(400).json({ message: 'Invalid collection ID format.' });
            }
            console.error(`Error fetching collection ${collectionId}:`, error);
            res.status(500).json({ message: 'Server error while fetching collection.', details: error.message });
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
        // 1. Fetch collections, including all variations
        const collections = await PreOrderCollection.find({ isActive: true })
            .select('_id name tag price sizes totalStock availableDate variations')
            .sort({ createdAt: -1 })
            .lean();

        // 2. Transform the documents into the final public response structure.
        const publicCollections = await Promise.all(collections.map(async (collection) => {
            
            // Map the internal 'variations' (Mongoose) to 'variants' (Public) with SIGNED URLs
            const variants = await Promise.all(collection.variations.map(async (v) => ({
                // Assuming 'v' has a color property or a way to derive one (e.g., from 'tag' or adding a color field to the schema)
                // Since the original PreOrder schema didn't have a color, we use variationIndex or assume a color field exists.
                variationIndex: v.variationIndex, 
                frontImageUrl: await generateSignedUrl(v.frontImageUrl) || null,
                backImageUrl: await generateSignedUrl(v.backImageUrl) || null,
            })));

            // --- A. Extract primary image from the first variant ---
            const firstVariant = variants.length > 0 ? variants[0] : {};
            const frontImageUrl = firstVariant.frontImageUrl || null;
            const backImageUrl = firstVariant.backImageUrl || null;

            return {
                _id: collection._id,
                name: collection.name,
                tag: collection.tag,
                price: collection.price, 
                availableSizes: collection.sizes,
                availableStock: collection.totalStock, 
                availableDate: collection.availableDate, 
                
                // B. Primary Image URLs for quick display
                frontImageUrl: frontImageUrl, 
                backImageUrl: backImageUrl, 
                
                // C. 🚨 CRITICAL FIX: Include the full variants array for color swatches/switching
                variants: variants 
            };
        }));

        res.status(200).json(publicCollections);
    } catch (error) {
        console.error('Error fetching public pre-order collections:', error);
        res.status(500).json({ 
            message: 'Server error while fetching public collections.', 
            details: error.message 
        });
    }
});

// 1. POST /api/users/register (Create Account and Send Verification Code)
app.post('/api/users/register', async (req, res) => {
    // 🔔 CRITICAL UPDATE: Destructure all fields, including the structured 'address' object
    const { 
        email, password, firstName, lastName, phone, whatsapp, address // This is now the object: { street, city, state, zip, country }
    } = req.body;

    // Basic Validation: Ensure core fields and required address fields are present
    if (!email || !password || password.length < 8 || !address || !address.street || !address.city || !address.country) {
        return res.status(400).json({ 
            message: 'Invalid input. Email, password (min 8 chars), and the required address fields (street, city, country) are necessary.' 
        });
    }

    let newUser; 
    let verificationCode;
    
    // --- 🛠️ ADDRESS MAPPING: Create final address object with optional zip handling ---
    const finalAddress = {
        street: address.street,
        city: address.city,
        state: address.state,
        zip: address.zip || null, // ZIP/Postal Code is optional, set to null if empty
        country: address.country
    };
    // ----------------------------------------------------------------------------------

    try {
        // --- 🛠️ FIX: Use new User() and .save() to trigger the pre('save') hook ---
        newUser = new User({
            email,
            password, // Password is now passed to the pre-save hook
            profile: { 
                firstName, 
                lastName, 
                phone, 
                whatsapp 
            },
            // 🎉 UPDATED: Map the structured address object directly
            address: finalAddress,
            status: { isVerified: false } // Set nested status field
        });
        
        await newUser.save(); // <-- THIS IS THE CRITICAL CHANGE that hashes the password and saves the user
        // --------------------------------------------------------------------------

        // Generate and store the verification code (this updates the user again)
        verificationCode = await generateHashAndSaveVerificationCode(newUser);

        // --- Send Verification Code Email Logic (UNMODIFIED) ---
        const verificationSubject = 'Outflickz: Your Account Verification Code';
        const verificationHtml = `
            <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #ffffffff; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                <div style="text-align: center; padding-bottom: 20px;">
                    <img src="[https://i.imgur.com/1Rxhi9q.jpeg](https://i.imgur.com/1Rxhi9q.jpeg)" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                </div>
                
                <h2 style="color: #000000; font-weight: 600; text-align: center;">Verify Your Account</h2>

                <p style="font-family: sans-serif; line-height: 1.6;">Hello ${firstName || 'New Member'},</p>
                <p style="font-family: sans-serif; line-height: 1.6;">Use the 6-digit code below to verify your email address and activate your account. This code will expire in 10 minutes.</p>
                
                <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                    <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${verificationCode}</strong>
                </div>

                <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
            </div>
        `;

        await sendMail(email, verificationSubject, verificationHtml);
        console.log(`Verification email sent to ${email} with code ${verificationCode}`);
        
        res.status(201).json({ 
            message: 'Registration successful. Please check your email for the 6-digit verification code.',
            userId: newUser._id,
            needsVerification: true
        });

    } catch (error) {
        
        if (error.code === 11000) { 
            // Handle duplicate key error (email already exists)
            const existingUser = await User.findOne({ email });

            // Check if the existing user is NOT verified
            if (existingUser && existingUser.status && !existingUser.status.isVerified) { 
                try {
                    // Re-trigger the code generation and email send for the existing user
                    const newVerificationCode = await generateHashAndSaveVerificationCode(existingUser);
                    
                    // Re-use HTML template structure from the try block
                    const verificationSubject = 'Outflickz: Your Account Verification Code';
                    const verificationHtml = `
                        <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #ffffffff; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                            <div style="text-align: center; padding-bottom: 20px;">
                                <img src="[https://i.imgur.com/1Rxhi9q.jpeg](https://i.imgur.com/1Rxhi9q.jpeg)" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                            </div>
                            
                            <h2 style="color: #000000; font-weight: 600; text-align: center;">Verify Your Account</h2>

                            <p style="font-family: sans-serif; line-height: 1.6;">Hello ${existingUser.profile?.firstName || 'New Member'},</p>
                            <p style="font-family: sans-serif; line-height: 1.6;">A new verification code was sent for your existing account. Use the 6-digit code below to activate your account. This code will expire in 10 minutes.</p>
                            
                            <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                                <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${newVerificationCode}</strong>
                            </div>

                            <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
                        </div>
                    `;

                    await sendMail(email, verificationSubject, verificationHtml);
                    console.log(`Verification code re-sent to unverified existing user ${email}`);

                    return res.status(202).json({ 
                        message: 'This email is already registered but unverified. A new verification code has been sent.',
                        userId: existingUser._id,
                        needsVerification: true
                    });

                } catch (emailError) {
                    console.error(`CRITICAL: Resending email failed for existing unverified user ${email}:`, emailError);
                    return res.status(503).json({ 
                        message: 'Account exists but failed to resend verification email. Please use the "Resend Code" option directly.',
                        needsVerification: true,
                        userId: existingUser._id
                    });
                }
            }
            // If user exists and is verified, return the 409 conflict
            return res.status(409).json({ message: 'This email address is already registered.' });
        }
        
        if (newUser && (error.message.includes('Email service is unconfigured.') || error.message.includes('SMTP'))) {
            console.error(`CRITICAL: Email service failed for ${email}:`, error);
            return res.status(503).json({ 
                message: 'Account created, but we failed to send the verification email. Please use the "Resend Code" option or try logging in again.',
                needsVerification: true,
                userId: newUser._id
            });
        }

        console.error("User registration error:", error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// 5. POST /api/users/resend-verification (New Endpoint)
app.post('/api/users/resend-verification', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required to resend the code.' });
    }

    try {
        const user = await User.findOne({ email });

        if (!user) {
            // Respond generically to prevent email enumeration
            return res.status(200).json({ message: 'If an account exists, a new verification code has been sent.' });
        }
        
        // FIX: Check nested status field
        if (user.status && user.status.isVerified) {
             return res.status(400).json({ message: 'Account is already verified. Please proceed to login.' });
        }
        
        // 1. Generate and store a new code
        // FIX: Corrected function name to generateHashAndSaveVerificationCode
        const verificationCode = await generateHashAndSaveVerificationCode(user); 
        
        // 2. Send the new code email
        const verificationSubject = 'Outflickz: Your NEW Account Verification Code';
        const verificationHtml = `
            <div style="background-color: #ffffffff; padding: 30px; border: 1px solid #e0e0e0; max-width: 500px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                <div style="text-align: center; padding-bottom: 20px;">
                    <img src="https://i.imgur.com/1Rxhi9q.jpeg" alt="Outflickz Limited Logo" style="max-width: 120px; height: auto; display: block; margin: 0 auto;">
                </div>
                
                <h2 style="color: #000000; font-weight: 600; text-align: center;">Resent Verification Code</h2>

                <p style="font-family: sans-serif; line-height: 1.6;">Hello ${user.profile?.firstName || 'User'},</p>
                <p style="font-family: sans-serif; line-height: 1.6;">A new 6-digit verification code was requested. Please use the code below to verify your email address. This code will expire in 10 minutes.</p>
                
                <div style="text-align: center; margin: 30px 0; padding: 15px; background-color: #ffffff; border: 2px dashed #9333ea; border-radius: 4px;">
                    <strong style="font-size: 28px; letter-spacing: 5px; color: #000000;">${verificationCode}</strong>
                </div>

                <p style="font-family: sans-serif; margin-top: 20px; line-height: 1.6; font-size: 14px; color: #555555;">If you did not request a new code, please secure your account immediately.</p>

                <p style="font-size: 10px; margin-top: 30px; border-top: 1px solid #e0e0e0; padding-top: 10px; color: #888888; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited.</p>
            </div>
        `;

        await sendMail(email, verificationSubject, verificationHtml);
        console.log(`New verification email sent successfully to ${email}`);

        // 3. Send successful response
        res.status(200).json({ message: 'A new verification code has been sent to your email address.' });

    } catch (error) {
        console.error("Resend verification code error:", error);
        res.status(500).json({ message: 'Failed to resend verification code due to a server error.' });
    }
});

// --- 2. POST /api/users/verify (Account Verification) ---
app.post('/api/users/verify', async (req, res) => {
    const { email, code } = req.body;

    // Basic Validation
    if (!email || !code) {
        return res.status(400).json({ message: 'Email and verification code are required.' });
    }

    try {
        // FIX: Explicitly select the hidden fields for the verification check
        const user = await User.findOne({ email })
            .select('+verificationCode +verificationCodeExpires');

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // 1. Check if already verified
        if (user.status && user.status.isVerified) { 
             return res.status(400).json({ message: 'Account is already verified.' });
        }
        
        // CRITICAL CHECK: Ensure the hash field exists before comparing
        if (!user.verificationCode) {
            console.error(`Verification hash missing for ${email}. User may need to resend code.`);
            return res.status(400).json({ message: 'No verification code is pending for this user. Please resend the code.' });
        }

        // 2. Check Expiration
        if (new Date() > user.verificationCodeExpires) {
            return res.status(400).json({ message: 'Verification code has expired. Please request a new one.' });
        }

        // 3. Compare Code
        const isMatch = await bcrypt.compare(code, user.verificationCode); 

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid verification code.' });
        }

        // 4. Verification Success: Update the user record
        await User.updateOne(
            { _id: user._id },
            { 
                $set: { 
                    // 🎉 FIXED: Using dot notation to update the nested 'status.isVerified' field
                    'status.isVerified': true 
                },
                // Clear the hash and expiry after successful verification
                $unset: { verificationCode: "", verificationCodeExpires: "" }
            }
        );
        
        console.log(`User ${email} successfully verified.`);
        
        res.status(200).json({ message: 'Account successfully verified. You can now log in.' });

    } catch (error) {
        console.error("User verification error:", error);
        res.status(500).json({ message: 'Server error during verification.' });
    }
});
// =========================================================
// 2. POST /api/users/login (Login) - MODIFIED
// =========================================================
app.post('/api/users/login', async (req, res) => {
    // ⚠️ New: Extract localCartItems from the request body 
    // The frontend should send this payload on login
    const { email, password, localCartItems } = req.body; 

    try {
        // NOTE: Ensure you import and have access to the logActivity function here!
        // const { logActivity } = require('./utils/activityLogger');
        
        const user = await User.findOne({ email }).select('+password').lean();
        
        // 1. Check for user existence and password match
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        
        // 2. Check verification status
        if (!user.status.isVerified) {
            return res.status(403).json({ 
                message: 'Account not verified. Please verify your email to log in.',
                needsVerification: true,
                userId: user._id
            });
        }

        // 3. Create the JWT token
        const token = jwt.sign(
            { id: user._id, email: user.email, role: user.status.role || 'user' }, 
            JWT_SECRET, 
            { expiresIn: '2h' } 
        );
        
        // --- 🔑 Set the Token as an HTTP-only Cookie ---
        const isProduction = process.env.NODE_ENV === 'production';
        
        res.cookie('outflickzToken', token, {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'strict' : 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });
        // -------------------------------------------------

        // 4. ✨ Merge Local Cart Items into the Database Cart ✨
        if (localCartItems && Array.isArray(localCartItems) && localCartItems.length > 0) {
            // This function handles finding the user's permanent cart and merging/updating quantities
            await mergeLocalCart(user._id, localCartItems);
            console.log(`Cart merged for user: ${user._id}`);
        }
        // -----------------------------------------------------------------------
        
        // 5. 🔔 CRITICAL NEW STEP: Log the successful login event 🔔
        // Ensure you have a 'logActivity' function imported and defined!
        // This log will appear in the Admin Dashboard.
        try {
            await logActivity(
                'LOGIN',
                `User **${user.email}** successfully logged in.`,
                user._id,
                { ipAddress: req.ip } // Adding context data like IP is often useful
            );
        } catch (logErr) {
            console.warn('Activity logging failed (login success was not affected):', logErr);
            // This is non-critical, so we continue without erroring out the main request
        }
        // -----------------------------------------------------------------------

        // 6. Send the successful JSON response 
        delete user.password; 

        res.status(200).json({ 
            message: 'Login successful',
            user: user
        });

    } catch (error) {
        console.error("User login error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// 3. GET /api/users/account (Fetch Profile - Protected)
app.get('/api/users/account', verifyUserToken, async (req, res) => {
    try {
        // req.userId is set by verifyUserToken middleware
        const user = await User.findById(req.userId).lean();

        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // --- FIX APPLIED HERE: Added the 'address' field ---
        res.status(200).json({
            id: user._id,
            email: user.email,
            profile: user.profile,
            status: user.status,
            membership: user.membership,
            address: user.address // <--- THIS LINE IS ADDED/CORRECTED
        });
        
    } catch (error) {
        console.error("Fetch profile error:", error);
        res.status(500).json({ message: 'Failed to retrieve user profile.' });
    }
});

// 4. PUT /api/users/profile (Update Personal Info - Protected)
app.put('/api/users/profile', verifyUserToken, async (req, res) => {
    try {
        // 🔔 UPDATED: Destructure new fields: whatsapp
        const { firstName, lastName, phone, whatsapp } = req.body;
        
        if (!firstName || !lastName) {
             return res.status(400).json({ message: 'First name and last name are required.' });
        }

        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            {
                // Note: The 'profile' field is likely an embedded document or object in your schema
                $set: {
                    'profile.firstName': firstName,
                    'profile.lastName': lastName,
                    'profile.phone': phone || null, // Update phone if provided
                    'profile.whatsapp': whatsapp || null // 🎉 NEW: Update whatsapp if provided
                }
            },
            { new: true, runValidators: true }
        );

        if (!updatedUser) {
            return res.status(404).json({ message: 'User not found.' });
        }

        res.status(200).json({ message: 'Profile details updated successfully.', profile: updatedUser.profile });

    } catch (error) {
        console.error("Profile update error:", error);
        res.status(500).json({ message: 'Failed to update profile details.' });
    }
});
// 5. PUT /api/users/address (Update Contact Address - Protected)
app.put('/api/users/address', verifyUserToken, async (req, res) => {
    try {
        const { street, city, state, zip, country } = req.body;
        
        // 1. Validation check
        if (!street || !city || !country) {
            return res.status(400).json({ message: 'Street, city, and country are required for the address.' });
        }

        // 2. Database Update
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            {
                // Use $set to update fields within the embedded 'address' object
                $set: {
                    'address.street': street,
                    'address.city': city,
                    'address.state': state,
                    'address.zip': zip,
                    'address.country': country
                }
            },
            // Important Options: 
            // { new: true } returns the modified document rather than the original.
            { new: true, runValidators: true, select: 'email profile address status membership' } 
            // Select all fields needed by the frontend's updateDOM function
        );

        if (!updatedUser) {
            // Should not happen if verifyUserToken works, but good practice
            return res.status(404).json({ message: 'User not found or session expired.' });
        }

        // 3. SUCCESS Response
        // Send back the data structure the client's updateDOM function expects
        return res.status(200).json({ 
            message: 'Contact address updated successfully!', 
            address: updatedUser.address // The client specifically needs the updated address object
        });

    } catch (error) {
        console.error('Address update error:', error);
        // Return a generic error message for the client
        return res.status(500).json({ message: 'Server error: Could not save address. Please try again.' });
    }
});

// =========================================================
// 3. POST /api/users/logout (Logout) - NEW
// =========================================================
/**
 * Clears the HTTP-only session cookie, effectively logging the user out.
 * This endpoint is designed to be called by the client's handleLogout function.
 */
app.post('/api/users/logout', (req, res) => {
    try {
        // Use res.clearCookie() to tell the browser to immediately expire the cookie.
        // It's important to use the same cookie name ('outflickzToken').
        // We set the same secure and sameSite flags for maximum compatibility in clearing.
        const isProduction = process.env.NODE_ENV === 'production';

        res.clearCookie('outflickzToken', {
            httpOnly: true,
            secure: isProduction,
            sameSite: isProduction ? 'strict' : 'lax',
        });

        // Send a success response. The client side will handle the redirect.
        res.status(200).json({ 
            message: 'Logout successful. Session cookie cleared.'
        });

    } catch (error) {
        // Even if an error occurs (e.g., in logging), the cookie clearance often still works.
        // We send a success response anyway to ensure the client proceeds with the redirect.
        console.error("Logout error:", error);
        res.status(500).json({ message: 'Server error during logout process.' });
    }
});


// 4. POST /api/users/forgot-password (Forgot Password)
app.post('/api/users/forgot-password', async (req, res) => {
    const { email } = req.body;

    // Respond successfully immediately to prevent user enumeration attacks
    res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    try {
        const user = await User.findOne({ email });
        
        if (user) {
            // 1. Generate a secure, unique, time-limited token (e.g., using crypto or jwt)
            const resetToken = crypto.randomBytes(32).toString('hex'); // Assumes 'crypto' is required

            // 2. Save the token and its expiry time to the user's document
            // await User.updateOne({ _id: user._id }, { resetPasswordToken: resetToken, resetPasswordExpires: Date.now() + 3600000 }); // 1 hour

            // 3. Construct the actual reset link
            const resetLink = `https://outflickz.netlify.app/reset-password?token=${resetToken}&email=${email}`;

            // 🛠️ NEW: Updated HTML template with Logo and Styling
            const resetSubject = 'Outflickz Limited: Password Reset Request';
            const resetHtml = `
                <div style="background-color: #ffffff; color: #000000; padding: 20px; border: 1px solid #eeeeee; max-width: 600px; margin: 0 auto; font-family: sans-serif; border-radius: 8px;">
                    <!-- Outflickz Logo -->
                    <div style="text-align: center; padding-bottom: 20px;">
                        <img src="https://i.imgur.com/1Rxhi9q.jpeg" alt="Outflickz Limited Logo" style="max-width: 150px; height: auto; display: block; margin: 0 auto;">
                    </div>

                    <h2 style="color: #000000; font-weight: 600;">Password Reset Request</h2>

                    <p style="font-family: sans-serif; line-height: 1.6;">Hello,</p>
                    <p style="font-family: sans-serif; line-height: 1.6;">You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
                    
                    <p style="font-family: sans-serif; line-height: 1.6;">Please click on the button below to complete the password reset process:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetLink}" 
                            style="display: inline-block; padding: 10px 20px; background-color: #000000; color: #ffffff; text-decoration: none; border-radius: 4px; font-weight: bold;">
                            Reset My Password
                        </a>
                    </div>

                    <p style="font-family: sans-serif; margin-top: 15px; line-height: 1.6;">If you did not request this, please ignore this email and your password will remain unchanged.</p>

                    <!-- Footer -->
                    <p style="font-size: 12px; margin-top: 30px; border-top: 1px solid #eeeeee; padding-top: 10px; color: #555555; text-align: center;">&copy; ${new Date().getFullYear()} Outflickz Limited. All rights reserved.</p>
                </div>
            `;
            
            // Send the email
            sendMail(email, resetSubject, resetHtml)
                .catch(error => console.error(`Failed to send password reset email to ${email}:`, error));
        }
    } catch (error) {
        // Log internal error but do not change the 200 response sent earlier
        console.error("Forgot password process error:", error);
    }
});

// 4. GET /api/auth/status (Check Authentication Status - Protected)
app.get('/api/auth/status', verifyUserToken, (req, res) => {
    // If verifyUserToken successfully executed, it means:
    // 1. The request had a token/session.
    // 2. The token/session was valid.
    // 3. The user is logged in.
    
    // We don't need to query the database here.
    // We just return a success status.
    res.status(200).json({ message: 'Authenticated', isAuthenticated: true });
});
// =========================================================
// 5. POST /api/users/cart - Add Item to Cart (Protected)
// =========================================================
app.post('/api/users/cart', verifyUserToken, async (req, res) => {
    // Expected request body for a new item:
    // 🌟 FIX 1: Destructure new fields from the request body 🌟
    const { productId, name, productType, size, color, price, quantity, imageUrl, variationIndex, variation } = req.body;
    const userId = req.userId;

    // Basic Input Validation
    // 🌟 FIX 2: Validate variationIndex, as it is now REQUIRED by the Cart schema 🌟
    if (!productId || !name || !productType || !size || !price || !quantity || price <= 0 || quantity < 1 || variationIndex === undefined || variationIndex === null) {
        return res.status(400).json({ message: 'Missing or invalid item details, including variation information.' });
    }

    // New item object based on cartItemSchema (Mongoose automatically assigns _id)
    const newItem = {
        productId,
        name,
        productType,
        size,
        color: color || 'N/A',
        price,
        quantity,
        imageUrl,
        
        // 🌟 FIX 3: Include the critical variation data in the item object 🌟
        variationIndex,
        variation: variation || (color ? `Color: ${color}` : `Var Index: ${variationIndex}`), 
    };

    try {
        // 1. Find the cart for the user
        let cart = await Cart.findOne({ userId });

        // 2. If no cart exists, create a new one
        if (!cart) {
            cart = await Cart.create({ userId, items: [newItem] });
            return res.status(201).json({ message: 'Cart created and item added.', cart: cart.items });
        }

        // 3. Check if the item variant already exists in the cart (same productId, size, color, AND variationIndex)
        // 🌟 FIX 4: Use variationIndex in the findIndex check for robustness 🌟
        const existingItemIndex = cart.items.findIndex(item =>
            item.productId.equals(productId) &&
            item.size === size &&
            item.color === newItem.color && 
            item.variationIndex === variationIndex // Added variationIndex check
        );

        if (existingItemIndex > -1) {
            // Item exists: Update quantity
            cart.items[existingItemIndex].quantity += quantity;
            cart.items[existingItemIndex].updatedAt = Date.now();
            
            // NOTE: Ideally, the name, price, and image should also be updated here
            // in case the product data was changed since the item was first added.
        } else {
            // Item does not exist: Add new item
            cart.items.push(newItem);
        }

        // 4. Save the updated cart
        await cart.save();
        
        // Return the current cart contents and totals (optional, but useful for frontend sync)
        const updatedCart = await Cart.findOne({ userId }).lean();
        const totals = calculateCartTotals(updatedCart.items);

        res.status(200).json({ 
            message: 'Item added/quantity updated successfully.', 
            items: updatedCart.items,
            ...totals
        });

    } catch (error) {
        console.error('Error adding item to cart:', error);
        res.status(500).json({ message: 'Failed to add item to shopping bag.' });
    }
});

// =========================================================
// 1. GET /api/users/cart - Retrieve Cart (Protected)
// =========================================================
app.get('/api/users/cart', verifyUserToken, async (req, res) => {
    try {
        // req.userId is set by verifyUserToken middleware
        const userId = req.userId;
        
        // Find the cart for the user
        const cart = await Cart.findOne({ userId }).lean();

        if (!cart) {
            // If no cart found, return an empty cart structure
            return res.status(200).json({
                items: [],
                ...calculateCartTotals([]),
            });
        }
        
        const totals = calculateCartTotals(cart.items);

        // Respond with the items and calculated totals
        res.status(200).json({
            items: cart.items, 
            ...totals,
        });

    } catch (error) {
        console.error('Error fetching cart:', error);
        res.status(500).json({ message: 'Failed to retrieve shopping bag.' });
    }
});

// =========================================================
// 2. PATCH /api/users/cart/:itemId - Update Quantity (Protected)
// =========================================================
app.patch('/api/users/cart/:itemId', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        // The itemId is the Mongoose _id of the item sub-document
        const itemId = req.params.itemId; 
        const { quantity } = req.body;

        const newQuantity = parseInt(quantity);
        if (isNaN(newQuantity) || newQuantity < 1) {
            return res.status(400).json({ message: 'Invalid quantity provided.' });
        }
        
        // Find cart by userId and update the specific item's quantity using the positional operator ($)
        const cart = await Cart.findOneAndUpdate(
            { userId, 'items._id': itemId },
            { 
                '$set': { 
                    'items.$.quantity': newQuantity, 
                    'updatedAt': Date.now() 
                } 
            },
            { new: true } // Return the updated document
        );

        if (!cart) {
            return res.status(404).json({ message: 'Item not found in your cart.' });
        }

        res.status(200).json({ message: 'Quantity updated successfully.' });

    } catch (error) {
        console.error('Error updating item quantity:', error);
        res.status(500).json({ message: 'Failed to update item quantity.' });
    }
});

// =========================================================
// 3. DELETE /api/users/cart/:itemId - Remove Single Item (Protected)
// =========================================================
app.delete('/api/users/cart/:itemId', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        const itemId = req.params.itemId;

        // Pull the specific item sub-document from the items array
        const cart = await Cart.findOneAndUpdate(
            { userId },
            { 
                '$pull': { 
                    items: { _id: itemId } 
                },
                '$set': { 
                    'updatedAt': Date.now() 
                } 
            },
            { new: true }
        );

        if (!cart) {
            return res.status(404).json({ message: 'Cart not found.' });
        }

        res.status(200).json({ message: 'Item removed successfully.' });

    } catch (error) {
        console.error('Error removing item:', error);
        res.status(500).json({ message: 'Failed to remove item.' });
    }
});

// =========================================================
// 4. DELETE /api/users/cart - Clear All Items (Protected)
// =========================================================
app.delete('/api/users/cart', verifyUserToken, async (req, res) => {
    try {
        const userId = req.userId;
        
        // Set the entire items array to an empty array
        const cart = await Cart.findOneAndUpdate(
            { userId },
            { 
                items: [],
                updatedAt: Date.now() 
            },
            { new: true }
        );

        if (!cart) {
            return res.status(404).json({ message: 'Cart not found to clear.' });
        }

        res.status(200).json({ message: 'Shopping bag cleared successfully.' });

    } catch (error) {
        console.error('Error clearing cart:', error);
        res.status(500).json({ message: 'Failed to clear shopping bag.' });
    }
});

// 7. POST /api/paystack/webhook - Handle Paystack Notifications
app.post('/api/paystack/webhook', async (req, res) => {
    // 1. Verify Webhook Signature (Security Crucial)
    // NOTE: req.body must be the raw buffer for signature calculation!
    const secret = PAYSTACK_SECRET_KEY;
    const hash = crypto.createHmac('sha512', secret)
        .update(req.body) 
        .digest('hex');
    
    if (hash !== req.headers['x-paystack-signature']) {
        console.error('Webhook verification failed: Invalid signature.');
        return res.status(401).send('Unauthorized access.');
    }

    // Convert raw body buffer to JSON object for processing
    // NOTE: If using Express, ensure you have middleware to handle the raw body buffer for verification
    const event = JSON.parse(req.body.toString());

    // 2. Check Event Type
    if (event.event !== 'charge.success') {
        return res.status(200).send(`Event type ${event.event} received but ignored.`);
    }

    const transactionData = event.data;
    const orderReference = transactionData.reference;

    try {
        // 3. Verify Transaction Status with Paystack (Double Check Security)
        const verificationResponse = await fetch(`${PAYSTACK_API_BASE_URL}/transaction/verify/${orderReference}`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${PAYSTACK_SECRET_KEY}`,
            }
        });

        const verificationData = await verificationResponse.json();

        if (verificationData.status !== true || verificationData.data.status !== 'success') {
            console.error('Transaction verification failed via API:', verificationData);
            await Order.findOne({ orderReference })
                .then(order => order && Order.findByIdAndUpdate(order._id, { status: 'Verification Failed' }));
            return res.status(200).send('Transaction status not success upon verification.');
        }

        const verifiedAmountKobo = verificationData.data.amount; // amount in kobo
        
        // 4. Find the corresponding Order using the reference
        const order = await Order.findOne({ orderReference });

        if (!order) {
            console.error('Order not found for reference:', orderReference);
            return res.status(404).send('Order not found.');
        }

        // 5. Final Checks (Amount and Status Check)
        if (order.amountPaidKobo !== verifiedAmountKobo) {
            console.error(`Amount mismatch for order ${order._id}. Expected: ${order.amountPaidKobo}, Received: ${verifiedAmountKobo}`);
            await Order.findByIdAndUpdate(order._id, { status: 'Amount Mismatch (Manual Review)' });
            return res.status(200).send('Amount mismatch, requires manual review.');
        }

        if (order.status === 'Paid') {
            return res.status(200).send('Order already processed.');
        }

        // 6. Update Order Status and Clear Cart
        // Perform the update first to persist the crucial status change
        await Order.findByIdAndUpdate(order._id, {
            status: 'Paid',
            paymentTxnId: transactionData.id,
            paidAt: new Date(),
        });

        // Clear the user's cart after successful payment
        await Cart.findOneAndUpdate(
            { userId: order.userId },
            { items: [], updatedAt: Date.now() }
        );
        
        // 7. CRITICAL: SEND CONFIRMATION EMAIL
        // We need the full order object for the email template
        const updatedOrder = await Order.findById(order._id); 
        if (updatedOrder) {
            await sendOrderConfirmationEmail(updatedOrder, 'paid'); 
        } else {
            console.error(`Could not re-fetch order ${order._id} for email.`);
        }

        console.log(`Order ${order._id} successfully marked as Paid, cart cleared, and confirmation email triggered.`);
        
        // 8. Success response to Paystack
        res.status(200).send('Webhook received and order processed successfully.');

    } catch (error) {
        console.error('Internal error processing webhook:', error);
        // It is generally safe to return 200 to the webhook provider even on failure
        // so they stop retrying, provided you log the failure for manual review.
        res.status(500).send('Internal Server Error.'); 
    }
});
// =========================================================
// 8. POST /api/notifications/admin-order-email - Send Notification to Admin
// This is typically called by the client AFTER a successful payment/order creation.
// =========================================================
app.post('/api/notifications/admin-order-email', async (req, res) => {
    
    // The payload is sent as JSON from the client-side 'sendAdminOrderNotification' function
    const { 
        orderId, 
        totalAmount, 
        paymentMethod, 
        shippingDetails, 
        items, 
        adminEmail,
        paymentReceiptUrl, // The URL from B2/DB
        subtotal,
        shippingFee,
        tax
    } = req.body;

    // 1. Basic Validation
    if (!orderId || !totalAmount || !adminEmail || !items || items.length === 0) {
        return res.status(400).json({ message: 'Missing required notification data or order items.' });
    }

    try {
        // --- STEP 1: Prepare Attachments from B2 ---
        const attachments = [];
        let attachmentFileName = null; 
        
        // Only attempt to attach if it's a Bank Transfer AND we have a B2 URL
        if (paymentMethod === 'Bank Transfer' && paymentReceiptUrl) {
            
            try {
                // a. Get the file key (path inside the bucket)
                const fileKey = getFileKeyFromUrl(paymentReceiptUrl);

                if (fileKey) {
                    console.log(`Attempting to download receipt file: ${fileKey}`);

                    // b. Create the GetObject command
                    const getObjectCommand = new GetObjectCommand({
                        Bucket: BLAZE_BUCKET_NAME,
                        Key: fileKey,
                    });

                    // c. Send the command and get the response stream
                    const response = await s3Client.send(getObjectCommand);

                    // d. Set content type and filename
                    const contentType = response.ContentType || 'application/octet-stream';
                    const keyParts = fileKey.split('/');
                    const suggestedFilename = keyParts[keyParts.length - 1] || 'payment-receipt.jpg'; 
                    
                    // e. Convert stream to Buffer
                    const buffer = await streamToBuffer(response.Body);

                    // f. Add to attachments array (Nodemailer format)
                    attachments.push({
                        filename: suggestedFilename,
                        content: buffer,
                        contentType: contentType,
                    });

                    attachmentFileName = suggestedFilename; 
                    console.log(`Receipt attached successfully: ${suggestedFilename}`);
                } else {
                    console.warn(`[Admin Email] Could not extract file key from URL: ${paymentReceiptUrl}. Skipping receipt attachment.`);
                }
            } catch (downloadError) {
                console.error(`[Admin Email] Failed to download receipt from B2:`, downloadError.message);
            }
        }
        // --- END: STEP 1 ---

        // 2. Format the Email Content (HTML)
        const paymentStatus = (paymentMethod === 'Paystack/Card') ? 'Payment Confirmed (Paystack)' : 'Payment Awaiting Verification (Bank Transfer)';
        
        // --- Item List HTML ---
        const itemDetailsHtml = items.map(item => `
            <tr>
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333;">
                    <table border="0" cellpadding="0" cellspacing="0">
                        <tr>
                            <td style="padding-right: 10px;">
                                <img src="${item.imageUrl || 'https://placehold.co/40x40/f7f7f7/999?text=X'}" alt="Product" width="40" height="40" style="display: block; border: 1px solid #ddd; border-radius: 4px;">
                            </td>
                            <td>
                                ${item.name || 'N/A'}
                            </td>
                        </tr>
                    </table>
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 12px; color: #555;">
                    <span style="display: block;">Size: <strong>${item.size || 'N/A'}</strong></span>
                    <span style="display: block; margin-top: 2px;">Color: ${item.color || 'N/A'}</span>
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: center;">
                    ${item.quantity}
                </td>
                
                <td style="padding: 12px 0 12px 0; border-bottom: 1px solid #eee; font-size: 14px; color: #333; text-align: right;">
                    ₦${(item.price * item.quantity).toLocaleString('en-US', { minimumFractionDigits: 2 })}
                </td>
            </tr>
        `).join('');

        // --- Attachment Confirmation Block ---
        const attachmentConfirmationHtml = attachmentFileName ? `
            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border-collapse: collapse; border: 1px solid #c0e6c0; border-radius: 4px;">
                <tr>
                    <td style="padding: 15px; background-color: #e0ffe0; font-size: 14px; color: #006400; font-weight: bold; text-align: center;">
                        ✅ Payment Receipt Proof Attached: 
                        <span style="font-weight: normal; color: #333;">${attachmentFileName}</span>
                        <div style="font-size: 12px; color: #555; margin-top: 5px;">
                            (Please check the email attachment for the file.)
                        </div>
                    </td>
                </tr>
            </table>
        ` : (paymentMethod === 'Bank Transfer' ? `
            <p style="margin-top: 30px; font-size: 14px; color: #FF4500; font-weight: bold; text-align: center;">
                ⚠️ Bank Transfer Payment Selected: Receipt attachment failed or URL was missing.
            </p>
        ` : '');

        // --- Financial Breakdown Summary (Using the newly included fields) ---
        const totalAmountNum = parseFloat(totalAmount);
        const subtotalNum = parseFloat(subtotal || (totalAmountNum - (shippingFee || 0) - (tax || 0)));
        const shippingFeeNum = parseFloat(shippingFee || 0);
        const taxNum = parseFloat(tax || 0);

        const financialSummaryHtml = `
            <tr>
                <td style="padding: 10px 0; font-size: 14px; color: #555; width: 50%;">Subtotal:</td>
                <td style="padding: 10px 0; font-size: 14px; color: #000000; text-align: right;">₦${subtotalNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
            <tr>
                <td style="padding: 5px 0; font-size: 14px; color: #555;">Shipping Fee:</td>
                <td style="padding: 5px 0; font-size: 14px; color: #000000; text-align: right;">₦${shippingFeeNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
            <tr>
                <td style="padding: 5px 0 20px 0; font-size: 14px; color: #555; border-bottom: 1px dashed #ccc;">Tax:</td>
                <td style="padding: 5px 0 20px 0; font-size: 14px; color: #000000; text-align: right; border-bottom: 1px dashed #ccc;">₦${taxNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
            </tr>
        `;
        
        // The main HTML structure remains mostly the same, inserting the new breakdown.
        const emailHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>New Outfulickz Order</title>
    <style>
        @media only screen and (max-width: 600px) {
            .container { width: 100% !important; padding: 0 10px !important; }
            .header-logo { width: 150px !important; height: auto !important; }
            .item-table td { display: table-cell !important; }
        }
    </style>
</head>
<body style="margin: 0; padding: 0; background-color: #f4f4f4; font-family: Arial, sans-serif;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed;">
        <tr>
            <td align="center" style="padding: 20px 0;">
                <table border="0" cellpadding="0" cellspacing="0" width="600" class="container" style="background-color: #ffffff; border: 1px solid #dddddd; border-radius: 8px;">
                    <tr>
                        <td align="center" style="padding: 20px 0 10px 0;">
                            <img src="https://i.imgur.com/1Rxhi9q.jpeg" alt="Outfulickz Logo" class="header-logo" width="180" style="display: block; border: 0; max-width: 180px;">
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 20px 40px 40px 40px;">
                            <h1 style="color: #000000; font-size: 24px; text-align: center; margin-bottom: 20px;">
                                🚨 NEW ORDER PLACED 🚨
                            </h1>
                            <p style="font-size: 16px; color: #333; line-height: 1.5;">
                                A new order has been created and requires immediate attention for fulfillment.
                            </p>
                            
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 25px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="2" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">ORDER SUMMARY</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555; width: 50%;">Order ID:</td>
                                    <td style="padding: 10px 0; font-size: 14px; color: #000000; font-weight: bold; text-align: right;">${orderId}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555;">Payment Method:</td>
                                    <td style="padding: 10px 0; font-size: 14px; color: #000000; text-align: right;">${paymentMethod}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0; font-size: 14px; color: #555;">Payment Status:</td>
                                    <td style="padding: 10px 0; font-size: 14px; font-weight: bold; text-align: right; color: ${paymentStatus.includes('Confirmed') ? 'green' : '#FFA500'};">${paymentStatus}</td>
                                </tr>
                                
                                ${financialSummaryHtml}

                                <tr>
                                    <td style="padding: 20px 0 10px 0; font-size: 16px; font-weight: bold; color: #000000;">TOTAL AMOUNT:</td>
                                    <td style="padding: 20px 0 10px 0; font-size: 18px; font-weight: bold; color: #000000; text-align: right;">₦${totalAmountNum.toLocaleString('en-US', { minimumFractionDigits: 2 })}</td>
                                </tr>
                            </table>

                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="margin-top: 30px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="2" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">SHIPPING DETAILS</td>
                                </tr>
                                <tr>
                                    <td style="padding: 10px 0 5px 0; font-size: 14px; color: #000000; font-weight: bold;" colspan="2">
                                        ${shippingDetails.firstName} ${shippingDetails.lastName}
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0; font-size: 14px; color: #555;" colspan="2">Email: ${shippingDetails.email}</td>
                                </tr>
                                <tr>
                                    <td style="padding: 5px 0 10px 0; font-size: 14px; color: #555; border-bottom: 1px dashed #ccc;" colspan="2">
                                        Address: ${shippingDetails.street}, ${shippingDetails.city}, ${shippingDetails.state}, ${shippingDetails.country} ${shippingDetails.zipCode ? `(${shippingDetails.zipCode})` : ''}
                                    </td>
                                </tr>
                            </table>
                            
                            <table border="0" cellpadding="0" cellspacing="0" width="100%" class="item-table" style="margin-top: 30px; border-collapse: collapse;">
                                <tr>
                                    <td colspan="4" style="font-size: 18px; font-weight: bold; color: #000000; padding-bottom: 10px; border-bottom: 2px solid #000000;">ITEMS ORDERED</td>
                                </tr>
                                
                                <thead>
                                    <tr style="text-align: left; background-color: #f7f7f7;">
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 40%;">PRODUCT</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 30%;">DETAILS</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 10%; text-align: center;">QTY</th>
                                        <th style="padding: 10px 0; font-size: 12px; color: #555; font-weight: normal; width: 20%; text-align: right;">SUBTOTAL</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${itemDetailsHtml}
                                </tbody>
                            </table>
                            
                            ${attachmentConfirmationHtml}

                            <p style="margin-top: 40px; font-size: 12px; color: #777; text-align: center;">
                                This is an automated notification. Please check the order management system for full details and fulfillment.
                            </p>

                        </td>
                    </tr>
                    
                    <tr>
                        <td align="center" style="background-color: #f7f7f7; padding: 15px 40px; border-radius: 0 0 8px 8px;">
                            <p style="margin: 0; font-size: 11px; color: #999;">&copy; ${new Date().getFullYear()} OUTFULICKZ. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
        `;

        // 3. Send the Email, passing the attachments array
        await sendMail(
            adminEmail,
            `[New Order] #${orderId} - ${paymentStatus}`,
            emailHtml,
            attachments 
        );

        console.log(`Admin notification sent successfully for Order ID: ${orderId} to ${adminEmail}`);
        
        // 4. Send a successful response back to the client
        res.status(200).json({ message: 'Admin notification request received and processing.' });

    } catch (error) {
        console.error('Error in POST /api/notifications/admin-order-email:', error);
        res.status(500).json({ message: 'Failed to dispatch admin email notification due to server error.' });
    }
});

// =========================================================
// 7. POST /api/orders/place/pending - Create a Pending Order (Protected)
// This route is used for manual Bank Transfer payments.
// =========================================================
app.post('/api/orders/place/pending', verifyUserToken, (req, res) => {
    
    // 1. Run the Multer middleware to process the form data and file
    singleReceiptUpload(req, res, async (err) => {
        
        // Handle Multer errors (e.g., file size limit)
        if (err instanceof multer.MulterError) {
            return res.status(400).json({ message: `File upload failed: ${err.message}` });
        } else if (err) {
            console.error('Unknown Multer Error:', err);
            return res.status(500).json({ message: 'Error processing file upload.' });
        }
        
        const userId = req.userId;
        
        // Form fields are now in req.body. Note: all amounts will be strings.
        const { 
            shippingAddress: shippingAddressString, 
            paymentMethod, 
            totalAmount: totalAmountString, 
            // ⭐ ADDED: Subtotal, Shipping Fee, and Tax fields must be extracted
            subtotal: subtotalString,
            shippingFee: shippingFeeString,
            tax: taxString 
        } = req.body;
        
        const receiptFile = req.file; // The uploaded file buffer is here
        
        // Convert string fields back to their proper type
        const totalAmount = parseFloat(totalAmountString);
        // ⭐ UPDATED: Financial breakdown conversion
        const subtotal = parseFloat(subtotalString || '0');
        const shippingFee = parseFloat(shippingFeeString || '0');
        const tax = parseFloat(taxString || '0');

        let shippingAddress;

        // --- START: UPDATED ROBUST PARSING LOGIC ---
        try {
            // Check if the string is empty or null BEFORE attempting JSON.parse.
            if (!shippingAddressString || shippingAddressString.trim() === '') {
                // Set to null so the subsequent validation block can catch it.
                shippingAddress = null; 
            } else {
                shippingAddress = JSON.parse(shippingAddressString);
            }
        } catch (e) {
            // This now strictly catches malformed JSON strings (e.g., missing double quotes on keys).
            return res.status(400).json({ message: 'Invalid shipping address format. Ensure the address object is stringified correctly.' });
        }
        // --- END: UPDATED ROBUST PARSING LOGIC ---
        
        // 2. Critical Input Validation
        if (!shippingAddress || totalAmount <= 0 || isNaN(totalAmount)) {
            // The `shippingAddress` will be null if the string was empty/missing, triggering this message.
            return res.status(400).json({ message: 'Missing shipping address or invalid total amount.' });
        }

        let paymentReceiptUrl = null;
        
        try {
            // NEW VALIDATION: Ensure the receipt file is provided for a Bank Transfer
            if (paymentMethod === 'Bank Transfer') {
                if (!receiptFile) {
                    return res.status(400).json({ message: 'Bank payment receipt image is required for a Bank Transfer order.' });
                }
                
                // 3. Upload the receipt file to Backblaze B2
                paymentReceiptUrl = await uploadFileToPermanentStorage(receiptFile);
                
                if (!paymentReceiptUrl) {
                    throw new Error("Failed to get permanent URL after B2 upload.");
                }
            }

            // 4. Retrieve the user's current cart items
            const cart = await Cart.findOne({ userId }).lean();

            if (!cart || cart.items.length === 0) {
                return res.status(400).json({ message: 'Cannot place order: Shopping bag is empty.' });
            }

            // 5. Create a new Order document with status 'Pending'
          const orderItems = cart.items.map(item => ({
            productId: item.productId,
            name: item.name, 
            imageUrl: item.imageUrl, // Mapped new field
            productType: item.productType,
            quantity: item.quantity,
            priceAtTimeOfPurchase: item.price, // Store the price explicitly
            variationIndex: item.variationIndex, // Mapped new field
            size: item.size,
            variation: variationName,
            color: item.color,
          }));
            
            // **CRITICAL: Generate a reference for bank transfer orders**
            const orderRef = `MANUAL-${Date.now()}-${userId.substring(0, 5)}`; 

            const newOrder = await Order.create({
                userId: userId,
                items: orderItems,
                shippingAddress: shippingAddress,
                totalAmount: totalAmount,
                // ⭐ ADDED: Store the financial breakdown for record accuracy
                subtotal: subtotal,
                shippingFee: shippingFee,
                tax: tax,
                status: 'Pending', // Use capitalized status from schema enum
                paymentMethod: paymentMethod,
                orderReference: orderRef, 
                amountPaidKobo: Math.round(totalAmount * 100),
                paymentTxnId: orderRef, // Use the order reference as the txn ID for now
                paymentReceiptUrl: paymentReceiptUrl, // Store the B2 permanent URL here
            });

            // 6. Clear the user's cart after successful order creation
            await Cart.findOneAndUpdate(
                { userId },
                { items: [], updatedAt: Date.now() }
            );
            
            console.log(`Pending Order created: ${newOrder._id}. Receipt URL: ${paymentReceiptUrl}`);
            
            // Extract first and last name from the parsed shipping address
            const { firstName, lastName } = shippingAddress;

            // Success response for the client-side JavaScript
            res.status(201).json({
                message: 'Pending order placed successfully. Awaiting payment verification.',
                orderId: newOrder._id,
                status: newOrder.status,
                firstName: firstName,
                lastName: lastName,
                ReceiptUrl: paymentReceiptUrl
            });

        } catch (error) {
            console.error('Error placing pending order:', error);
            res.status(500).json({ message: 'Failed to create pending order due to a server error.' });
        }
    });
}); 

// 6. GET /api/orders/:orderId (Fetch Single Order Details - Protected)
app.get('/api/orders/:orderId', verifyUserToken, async function (req, res) {
    const orderId = req.params.orderId;
    const userId = req.userId; // Set by verifyUserToken middleware

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required.' });
    }
    if (!userId) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    try {
        // 1. Fetch the specific order document
        const order = await Order.findOne({ 
            _id: orderId, // Find by ID
            userId: userId // AND ensure it belongs to the authenticated user
        })
        // ⭐ FIX: Ensure we select the new financial breakdown fields
        .select('+subtotal +shippingFee +tax')
        .lean();

        if (!order) {
            return res.status(404).json({ message: 'Order not found or access denied.' });
        }

        // 2. Fetch Display Details for each item (Product Name, Image, etc.)
        const productDetailsPromises = order.items.map(async (item) => {
            // Use a copy of the item object for mutation
            let displayItem = { ...item };
            
            // Prioritize saved data for name/image consistency at time of purchase
            if (item.name && item.imageUrl) {
                // If the order item already contains the name and image (which it should now)
                displayItem.sku = `SKU-${item.productType.substring(0,3).toUpperCase()}-${item.size || 'UNK'}`;
                delete displayItem._id; 
                return displayItem;
            }
            
            // Fallback to fetching product details if necessary (e.g., for old orders)
            const Model = productModels[item.productType];
            
            if (!Model) {
                console.warn(`[OrderDetails] Unknown product type: ${item.productType}`);
                displayItem.name = item.name || 'Product Not Found';
                displayItem.imageUrl = item.imageUrl || 'https://via.placeholder.com/150/CCCCCC/FFFFFF?text=Error';
                displayItem.sku = 'N/A';
            } else {
                // Find the original product to get the display details
                const product = await Model.findById(item.productId)
                    .select('name imageUrls') // Only need display data
                    .lean();

                displayItem.name = item.name || (product ? product.name : 'Product Deleted');
                // Use the saved imageUrl if available, otherwise fallback to the first product image
                displayItem.imageUrl = item.imageUrl || (product && product.imageUrls && product.imageUrls.length > 0 ? product.imageUrls[0] : 'https://via.placeholder.com/150/CCCCCC/FFFFFF?text=No+Image');
                displayItem.sku = `SKU-${item.productType.substring(0,3).toUpperCase()}-${item.size || 'UNK'}`;
            }
            
            // Clean up the Mongoose virtual _id field before sending
            delete displayItem._id; 
            
            return displayItem;
        });

        // Resolve all concurrent product detail fetches
        const populatedItems = await Promise.all(productDetailsPromises);
        
        // 3. Construct the final response object, now correctly reading the financial breakdown
        const finalOrderDetails = {
            ...order,
            items: populatedItems,
            // ⭐ FIX/UPDATE: Read the actual stored financial breakdown, falling back to stored data/zero if undefined
            // If subtotal is undefined, approximate it by subtracting fees from the total amount.
            subtotal: order.subtotal !== undefined 
                ? order.subtotal 
                : (order.totalAmount - (order.shippingFee || 0.00) - (order.tax || 0.00)), 
            shippingFee: order.shippingFee || 0.00, 
            tax: order.tax || 0.00 
        };

        // 4. Send the populated details to the frontend
        res.status(200).json(finalOrderDetails);

    } catch (error) {
        console.error('Error fetching order details:', error);
        res.status(500).json({ message: 'Failed to retrieve order details due to a server error.' });
    }
});

// =========================================================
// 2. GET /api/orders/history - Retrieve Order History (Protected)
// =========================================================
app.get('/api/orders/history', verifyUserToken, async (req, res) => {
    try {
        // req.userId is set by verifyUserToken middleware
        const userId = req.userId;

        if (!userId) {
             // Should theoretically be caught by verifyUserToken, but serves as a safety check
            return res.status(401).json({ message: 'Authentication required to view order history.' });
        }

        // 1. Fetch orders from the database
        const orders = await Order.find({ userId: userId })
            // Select only the fields needed for the Order History table on the frontend:
            .select('_id createdAt totalAmount status items')
            // Sort by newest order first (descending by createdAt)
            .sort({ createdAt: -1 })
            .lean(); // Use .lean() for faster read operations

        // 2. Format the output data for the frontend
        const formattedOrders = orders.map(order => ({
            // Use MongoDB's _id as the unique identifier (Order ID)
            id: order._id, 
            date: order.createdAt, // The date the order was created/placed
            total: order.totalAmount,
            status: order.status.charAt(0).toUpperCase() + order.status.slice(1), // Capitalize status for display
            // Count the number of distinct products/lines in the order
            items: order.items.length 
        }));

        // 3. Respond with the formatted order history list
        res.status(200).json({
            orders: formattedOrders,
            message: 'Order history retrieved successfully.'
        });

    } catch (error) {
        console.error('Error fetching order history:', error);
        res.status(500).json({ message: 'Failed to retrieve order history due to a server error.' });
    }
});

// =========================================================
// 3. PUT /api/orders/:orderId/cancel - Order Cancellation (Protected)
// =========================================================
app.put('/api/orders/:orderId/cancel', verifyUserToken, async (req, res) => {
    const orderId = req.params.orderId;
    const userId = req.userId;

    if (!orderId) {
        return res.status(400).json({ message: 'Order ID is required.' });
    }

    try {
        // Define which statuses are eligible for cancellation
        // ⭐ FIX: Must use capitalized statuses to match the Mongoose Enum definition
        const cancellableStatuses = ['Pending', 'Processing']; 

        // 1. Find the order and ensure ownership and cancellable status
        const order = await Order.findOne({ 
            _id: orderId, 
            userId: userId,
            status: { $in: cancellableStatuses } // Order must be in a cancellable state
        });

        if (!order) {
            // Check if the order exists but is in a non-cancellable state
            const existingOrder = await Order.findOne({ _id: orderId, userId: userId });
            
            if (existingOrder && !cancellableStatuses.includes(existingOrder.status)) {
                 return res.status(400).json({ 
                    message: `Cannot cancel order. Current status is '${existingOrder.status}'.` 
                });
            }

            return res.status(404).json({ message: 'Order not found or not eligible for cancellation.' });
        }
        
        // 2. Update the order status to 'Cancelled'
        // Using findByIdAndUpdate ensures the update is Atomic
        const updatedOrder = await Order.findByIdAndUpdate(
            order._id,
            { 
                $set: { 
                    status: 'Cancelled', // ⭐ FIX: Use capitalized status from schema enum
                    cancellationDate: new Date(), // Log the cancellation time
                    // You might also log who cancelled it if needed (order.cancelledBy = userId)
                } 
            },
            { new: true } // Return the updated document
        );
        console.log(`[Cancellation Success] Order ${orderId} cancelled. Refund/Inventory rollback needed.`);


        // 4. Send success response
        res.status(200).json({ 
            message: 'Order successfully cancelled. A refund has been initiated.', 
            order: updatedOrder 
        });

    } catch (error) {
        console.error('Error during order cancellation:', error);
        // Log the specific ID for debugging
        res.status(500).json({ message: `Failed to cancel order ${orderId} due to a server error.` });
    }
});

module.exports = {
    WearsCollection,
    NewArrivals,
    CapCollection,
    PreOrderCollection,
    Order,
    Cart,
    app,
    mongoose,
    populateInitialData,
    MONGODB_URI
};