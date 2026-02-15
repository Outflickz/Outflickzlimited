const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const AWS = require('aws-sdk');
const sharp = require('sharp'); 
const nodemailer = require('nodemailer');

// Configuration from Environment Variables
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const MASTER_ACCESS_KEY = (process.env.MASTER_ACCESS_KEY || '').trim();
const BUCKET_NAME = (process.env.IDRIVE_BUCKET_NAME || '').trim();

// IDRIVE / S3 CONFIGURATION
const rawEndpoint = process.env.IDRIVE_ENDPOINT;
const s3Config = {
    accessKeyId: (process.env.IDRIVE_ACCESS_KEY || '').trim(), 
    secretAccessKey: (process.env.IDRIVE_SECRET_KEY || '').trim(),
    region: process.env.IDRIVE_REGION,
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
};

if (rawEndpoint) {
    s3Config.endpoint = new AWS.Endpoint(rawEndpoint);
}
const s3 = new AWS.S3(s3Config);

// DATABASE CONNECTION POOLING
let cachedDb = null;

async function connectToDatabase() {
    if (cachedDb) return cachedDb;
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    cachedDb = client.db('Outflickz_data'); 
    return cachedDb;
}

/**
 * HELPER: Upload Base64 to Private IDrive/S3 with Compression
 */
async function uploadToS3(fileBase64) {
    if (!fileBase64) return null;

    try {
        // Remove the data URL prefix (e.g., data:image/jpeg;base64,)
        const base64Data = fileBase64.replace(/^data:image\/\w+;base64,/, "");
        const buffer = Buffer.from(base64Data, 'base64');

        // 2. IMAGE PROCESSING PIPELINE
        const compressedBuffer = await sharp(buffer)
            .rotate() // Auto-rotates based on EXIF data (fixes sideways phone uploads)
            .resize(1000, 1333, { 
                fit: 'cover', 
                withoutEnlargement: true 
            }) // Standardize to a 3:4 aspect ratio common for streetwear
            .webp({ quality: 75, effort: 4 }) // Convert to WebP with 75% quality
            .toBuffer();

        // Use .webp extension for the key
        const key = `vault/${Date.now()}-${Math.random().toString(36).substring(7)}.webp`;

        const params = {
            Bucket: BUCKET_NAME,
            Key: key,
            Body: compressedBuffer,
            ContentType: 'image/webp',
            // 3. CACHE CONTROL (Crucial for bad network performance)
            // Tells the browser to keep the image for 1 year so it doesn't re-download
            CacheControl: 'public, max-age=31536000, immutable'
        };

        await s3.upload(params).promise();
        return key; 
    } catch (error) {
        console.error("Compression/Upload Error:", error);
        // Fallback: If sharp fails, return null or handle accordingly
        return null;
    }
}

/**
 * HELPER: Generate Temporary Secure Link
 * Valid for 72 hours (3 Days)
 */
async function getSecureUrl(key) {
    if (!key || typeof key !== 'string') return null;
    
    // If it's already a full URL, return it as is
    if (key.startsWith('http')) return key;
    
    // SANITIZE: Remove any accidental ellipsis (…) or whitespace 
    // that might have been stored in the DB during a bad upload.
    const cleanKey = key.replace(/[…\s]/g, '').trim();
    
    try {
        // Generate the Signed URL
        // 43200 (12h) -> 259200 (72h)
        return await s3.getSignedUrlPromise('getObject', {
            Bucket: BUCKET_NAME,
            Key: cleanKey,
            Expires: 259200 
        });
    } catch (err) {
        console.error("S3 Signing Error for key:", cleanKey, err);
        return null;
    }
}

const transporter = nodemailer.createTransport({
    service: 'gmail',
    pool: true, 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS 
    },
    // Add these to prevent timeout issues
    debug: true,
    logger: true 
});
async function sendOrderEmails(order, status = 'New') {
    if (!order || !order.email) {
        console.error("EMAIL_ABORTED: No recipient email found.");
        return;
    }

    // 1. Generate Signed URLs for the private images
    const signedItems = await Promise.all((order.items || []).map(async (item) => {
        let displayImage = 'https://via.placeholder.com/200x250?text=No+Image';
        if (item.image) {
            try {
                displayImage = await getSecureUrl(item.image);
            } catch (err) {
                console.error("SIGNING_ERROR_FOR_EMAIL:", err);
            }
        }
        return { ...item, signedImage: displayImage };
    }));

    // 2. Updated Financial Calculations
    // Subtotal based on items
    const subtotal = signedItems.reduce((acc, item) => acc + (Number(item.price || 0) * Number(item.qty || 1)), 0);
    
    // Support both naming conventions (shippingCost or shippingFee)
    const shipping = Number(order.shippingFee || order.shippingCost || 0);
    
    // Support both naming conventions (tax or taxAmount)
    const tax = Number(order.taxAmount || order.tax || 0);
    
    const total = subtotal + shipping + tax;

    const fromAddress = `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_USER}>`;
    const logoUrl = "https://i.imgur.com/fu8N7I2.jpeg";

    // 3. Pickup vs Shipping Detection Logic
    const isPickup = (order.deliveryMethod === 'pickup');
    const refSuffix = (order.reference || '000').slice(-6).toUpperCase();

    // 4. Dynamic Status & Logistics Copy
    let headline, subHeadline, mainMessage, subject;

    if (status === 'Shipped') {
        headline = isPickup ? "READY FOR COLLECTION" : "DISPATCH INITIALIZED";
        subHeadline = isPickup ? "ORDER AT PICKUP POINT" : "ORDER ITEMS IN TRANSIT";
        mainMessage = isPickup 
            ? `Hi ${order.firstName}, your selection is ready. You can now visit our ${order.pickupLocation || 'designated branch'} to collect your package. Please have your Order ID ready.`
            : `Hi ${order.firstName}, your selection has been cleared from our vault and is currently on its way to your location. Prepare for arrival.`;
        subject = isPickup ? `OUTFLICKZ: READY FOR PICKUP #${refSuffix}` : `OUTFLICKZ: YOUR SELECTION IS IN TRANSIT #${refSuffix}`;
    } else if (status === 'Delivered') {
        headline = "COLLECTION SECURED";
        subHeadline = isPickup ? "PICKUP COMPLETED" : "PACKAGE SUCCESSFULLY DELIVERED";
        mainMessage = `Your package has been successfully ${isPickup ? 'picked up' : 'delivered'}! We hope you enjoy your new OUTFLICKZ collection. Thank you for your patronage—it’s been a pleasure serving you.`;
        subject = `OUTFLICKZ: COMPLETED #${refSuffix}`;
    } else {
        headline = "ORDER SELECTION SECURED";
        subHeadline = "TRANSACTION VERIFIED";
        mainMessage = `Hi ${order.firstName}, thank you for your order. We are officially preparing your selection. ${isPickup ? "We will notify you the moment it is ready at the pickup branch." : "Stay ready for dispatch."}`;
        subject = `THANK YOU: VAULT SECURED #${refSuffix}`;
    }

    // 5. Build Items HTML
    const itemsHtml = signedItems.map(item => `
        <tr>
            <td style="padding: 10px 0;">
                <table width="100%" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border: 1px solid #e0e0e0; border-bottom: 4px solid #000000; border-radius: 8px;">
                    <tr>
                        <td width="100" style="padding: 15px;">
                            <img src="${item.signedImage}" width="80" style="width: 80px; height: auto; display: block; filter: grayscale(100%); border-radius: 4px; border: 1px solid #eee;">
                        </td>
                        <td style="padding: 15px 15px 15px 0;" valign="middle">
                            <p style="margin: 0; font-family: sans-serif; font-size: 13px; font-weight: 900; text-transform: uppercase; letter-spacing: 1px; color: #000;">${item.name || 'Vault Item'}</p>
                            <p style="margin: 4px 0; font-family: sans-serif; font-size: 10px; color: #888; text-transform: uppercase;">${item.color || 'Default'} / ${item.size || item.displaySize || 'OS'}</p>
                            <p style="margin: 0; font-family: sans-serif; font-size: 11px; font-weight: bold; color: #000;">QTY: ${item.qty || 1}</p>
                        </td>
                        <td align="right" style="padding-right: 20px;" valign="middle">
                            <p style="margin: 0; font-family: sans-serif; font-size: 13px; font-weight: 900; color: #000;">₦${(Number(item.price || 0) * Number(item.qty || 1)).toLocaleString()}</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    `).join('');

    // 6. Build Master Template
    const emailTemplate = (isForAdmin = false) => `
    <!DOCTYPE html>
    <html>
    <head><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body style="margin: 0; padding: 0; background-color: #f0f0f0; font-family: sans-serif;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f0f0f0; padding: 40px 0;">
            <tr>
                <td align="center">
                    <table width="550" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 12px; border: 1px solid #dddddd; border-bottom: 8px solid #000000; box-shadow: 0 20px 40px rgba(0,0,0,0.1); padding: 40px;">
                        <tr>
                            <td align="center" style="padding-bottom: 30px;">
                                <img src="${logoUrl}" alt="OUTFLICKZ" width="120" style="width: 120px; display: block; margin: 0 auto;">
                                <h1 style="margin: 10px 0 0 0; font-size: 24px; font-weight: 900; letter-spacing: 6px; color: #000000; text-transform: uppercase;">OUTFLICKZ</h1>
                                <div style="width: 40px; height: 2px; background-color: #000; margin: 15px auto 0;"></div>
                            </td>
                        </tr>
                        <tr>
                            <td style="background-color: #000000; padding: 12px; border-radius: 4px; text-align: center; margin-bottom: 25px;">
                                <p style="margin: 0; font-size: 11px; font-weight: 900; text-transform: uppercase; letter-spacing: 3px; color: #ffffff;">
                                    ${isForAdmin ? 'INTERNAL: NEW ORDER DETECTED' : headline}
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 30px 0 10px 0;">
                                <h2 style="margin: 0; font-size: 18px; font-weight: 900; color: #000; text-transform: uppercase;">
                                    ${isForAdmin ? `Order From: ${order.firstName} ${order.lastName}` : subHeadline}
                                </h2>
                                <p style="margin: 10px 0; font-size: 14px; line-height: 1.6; color: #444;">
                                    ${isForAdmin ? `A new ${order.deliveryMethod} transaction has been processed. Immediate action required.` : mainMessage}
                                </p>
                            </td>
                        </tr>
                        <table width="100%" cellspacing="0" cellpadding="0">${itemsHtml}</table>
                        <tr>
                            <td style="padding-top: 30px;">
                                <table width="100%" cellspacing="0" cellpadding="8" style="background-color: #f9f9f9; border-radius: 8px; font-size: 11px; text-transform: uppercase; font-weight: bold; color: #888;">
                                    <tr><td>Subtotal</td><td align="right" style="color: #000;">₦${subtotal.toLocaleString()}</td></tr>
                                    <tr><td>Tax / VAT</td><td align="right" style="color: #000;">₦${tax.toLocaleString()}</td></tr>
                                    <tr><td>${isPickup ? 'Pickup Fee' : 'Shipping'}</td><td align="right" style="color: #000;">₦${shipping.toLocaleString()}</td></tr>
                                    <tr style="font-size: 16px; color: #000;">
                                        <td style="padding-top: 15px; border-top: 2px solid #000;">TOTAL PAID</td>
                                        <td align="right" style="padding-top: 15px; border-top: 2px solid #000; font-weight: 900;">₦${total.toLocaleString()}</td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        <tr>
                            <td style="padding-top: 30px;">
                                <div style="border: 2px dashed #000; border-radius: 8px; padding: 20px; font-family: sans-serif;">
                                    <p style="font-size: 12px; font-weight: 900; margin-bottom: 10px; text-transform: uppercase;">${isPickup ? 'Collection Details' : 'Logistics & Shipping Data'}:</p>
                                    <p style="font-size: 13px; margin: 5px 0;"><strong>Method:</strong> ${isPickup ? 'Local Pickup' : 'Standard Shipping'}</p>
                                    
                                    ${isPickup ? `
                                        <p style="font-size: 13px; margin: 5px 0;"><strong>Branch:</strong> ${order.pickupLocation || 'Warehouse Main'}</p>
                                        <p style="font-size: 11px; color: #888; margin-top: 10px; text-transform: uppercase;">* Show this email at the counter for verification.</p>
                                    ` : `
                                        <p style="font-size: 13px; margin: 10px 0 5px 0;"><strong>Shipping Address:</strong></p>
                                        <p style="font-size: 13px; margin: 0; color: #000; line-height: 1.4;">
                                            ${order.address || 'N/A'}<br>
                                            ${order.city || ''}, ${order.state || ''}
                                        </p>
                                    `}
                                    <p style="font-size: 13px; margin: 10px 0 0 0;"><strong>Reference:</strong> ${order.reference}</p>
                                </div>
                            </td>
                        </tr>
                        <tr><td align="center" style="padding-top: 50px;"><p style="font-size: 9px; color: #bbb; letter-spacing: 2px;">OUTFLICKZ &copy; 2026. SECURE ORDER TRANSACTION.</p></td></tr>
                    </table>
                </td>
            </tr>
        </table>
    </body>
    </html>`;

    // 7. Execution Logic
    try {
        const adminSubject = `⚡ [${order.deliveryMethod?.toUpperCase()}] New Order ₦${total.toLocaleString()} - ${order.firstName}`;

        const tasks = [
            transporter.sendMail({
                from: fromAddress,
                to: order.email,
                subject: subject,
                html: emailTemplate(false),
                text: mainMessage
            })
        ];

        if (status === 'New') {
            tasks.push(transporter.sendMail({
                from: fromAddress,
                to: process.env.ADMIN_EMAIL,
                subject: adminSubject,
                html: emailTemplate(true),
                text: `New ${order.deliveryMethod} Order from ${order.firstName}.`
            }));
        }

        await Promise.all(tasks);
        console.log(`EMAILS_SENT_SUCCESSFULLY: ${order.reference} (Mode: ${order.deliveryMethod})`);
    } catch (error) {
        console.error("EMAIL_TRANSPORT_ERROR:", error.message);
    }
}

async function sendVerificationEmail(email, otp, firstName) {
    const fromAddress = `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_USER}>`;
    const logoUrl = "https://i.imgur.com/fu8N7I2.jpeg";

    const otpTemplate = `
    <div style="background-color: #f0f0f0; padding: 40px; font-family: sans-serif; text-align: center;">
        <div style="max-width: 450px; margin: 0 auto; background: #fff; padding: 40px; border-bottom: 8px solid #000; border-radius: 12px;">
            <img src="${logoUrl}" width="100" style="margin-bottom: 20px;">
            <h2 style="letter-spacing: 4px; text-transform: uppercase; font-weight: 900;">IDENTITY VERIFICATION</h2>
            <p style="color: #666; font-size: 14px;">Hi ${firstName}, use the vault access code below to verify your account.</p>
            
            <div style="margin: 30px 0; padding: 20px; border: 2px dashed #000; border-radius: 8px; background: #fafafa;">
                <span style="font-size: 32px; font-weight: 900; letter-spacing: 10px; color: #000;">${otp}</span>
            </div>
            
            <p style="font-size: 11px; color: #999; text-transform: uppercase;">This code is valid for 10 minutes. If you did not request this, ignore this email.</p>
        </div>
        <p style="font-size: 10px; color: #bbb; margin-top: 20px;">OUTFLICKZ &copy; 2026 SECURE REGISTRATION</p>
    </div>
    `;

    try {
        await transporter.sendMail({
            from: fromAddress,
            to: email,
            subject: `VERIFY YOUR OUTFLICKZ ACCESS: ${otp}`,
            html: otpTemplate,
            text: `Your OUTFLICKZ verification code is: ${otp}`
        });
    } catch (error) {
        console.error("OTP_EMAIL_ERROR:", error);
    }
}

exports.handler = async (event, context) => {
    context.callbackWaitsForEmptyEventLoop = false;

    const headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Content-Type": "application/json"
    };

    if (event.httpMethod === "OPTIONS") return { statusCode: 200, headers, body: "OK" };

   try {
        const db = await connectToDatabase();

        const queryAction = event.queryStringParameters && event.queryStringParameters.action;
        const body = JSON.parse(event.body || "{}");
        const bodyAction = body.action;
        const action = queryAction || bodyAction;

        switch (action) {
          case 'add-wear': {
                const { name, price, description, variants } = body;

                const processedVariants = [];
                if (variants && Array.isArray(variants)) {
                    for (const v of variants) {
                        const variantImgKeys = [];
                        if (v.images && Array.isArray(v.images)) {
                            for (const imgBase64 of v.images) {
                                const key = await uploadToS3(imgBase64);
                                if (key) variantImgKeys.push(key);
                            }
                        }
                        processedVariants.push({
                            color: v.color,
                            stockMatrix: v.stockMatrix || {},
                            images: variantImgKeys 
                        });
                    }
                }

                const result = await db.collection('wears').insertOne({
                    name,
                    price: parseFloat(price),
                    variants: processedVariants,
                    description,
                    createdAt: new Date()
                });
                
                return { statusCode: 201, headers, body: JSON.stringify(result) };
            }

     case 'get-wears': {
    const wears = await db.collection('wears').find({}).sort({ createdAt: -1 }).toArray();
    
    const wearsWithLinks = await Promise.all(wears.map(async (wear) => {
        // 1. FALLBACK LOGIC: Identify the best available image source
        // If global displayImage is missing, grab the very first image from the first variant
        let imageToSign = wear.displayImage;
        if (!imageToSign && wear.variants?.[0]?.images?.[0]) {
            imageToSign = wear.variants[0].images[0];
        }

        // 2. SIGN THE DISPLAY IMAGE
        let signedDisplayImage = imageToSign;
        if (imageToSign && typeof imageToSign === 'string' && !imageToSign.startsWith('http') && !imageToSign.includes('…')) {
            signedDisplayImage = await getSecureUrl(imageToSign);
        }

        // 3. SIGN ALL VARIANT IMAGES
        const signedVariants = await Promise.all((wear.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(async (k) => {
                // Only call getSecureUrl if k is a S3 KEY, not a full URL
                if (typeof k === 'string' && !k.startsWith('http') && !k.includes('…')) {
                    return await getSecureUrl(k);
                }
                return k; 
            }));
            return { ...v, images: vImgs };
        }));

        // 4. RETURN MERGED OBJECT
        return { 
            ...wear, 
            displayImage: signedDisplayImage, 
            variants: signedVariants 
        };
    }));

    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Prevents browser from caching expired links
        }, 
        body: JSON.stringify(wearsWithLinks) 
    };
}

            case 'get-wear-details': {
                const { id } = body;
                if (!id) throw new Error("ID required");
                const product = await db.collection('wears').findOne({ _id: new ObjectId(id) });
                if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
                
                // Sign main gallery
                const signedImages = await Promise.all((product.images || []).map(key => getSecureUrl(key)));
                
                // Sign variant images
                const signedVariants = await Promise.all((product.variants || []).map(async v => {
                    const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
                    return { ...v, images: vImgs };
                }));

                return { statusCode: 200, headers, body: JSON.stringify({ ...product, images: signedImages, variants: signedVariants }) };
            }

           case 'update-wear': {
                const { id, name, price, description, variants } = body;
                if (!id) throw new Error("ID required");

                const existing = await db.collection('wears').findOne({ _id: new ObjectId(id) });
                if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

                const finalVariants = await Promise.all((variants || []).map(async (v) => {
                    const vImgKeys = [];
                    if (v.images && Array.isArray(v.images)) {
                        for (const img of v.images) {
                            // If it's a new base64 string, upload it
                            if (typeof img === 'string' && img.startsWith('data:')) {
                                const key = await uploadToS3(img);
                                if (key) vImgKeys.push(key);
                            } else {
                                // Keep existing key/URL
                                vImgKeys.push(img);
                            }
                        }
                    }
                    return {
                        color: v.color,
                        stockMatrix: v.stockMatrix || {},
                        images: vImgKeys
                    };
                }));

                await db.collection('wears').updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { name, price: parseFloat(price), description, variants: finalVariants, updatedAt: new Date() } }
                );
                
                return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
            }

            case 'delete-wear': {
                const { id } = body;
                await db.collection('wears').deleteOne({ _id: new ObjectId(id) });
                return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
            }

            case 'add-short': {
                const { name, price, description, variants } = body;

                const processedVariants = [];
                if (variants && Array.isArray(variants)) {
                    for (const v of variants) {
                        const variantImgKeys = [];
                        if (v.images && Array.isArray(v.images)) {
                            for (const imgBase64 of v.images) {
                                const key = await uploadToS3(imgBase64);
                                if (key) variantImgKeys.push(key);
                            }
                        }
                        processedVariants.push({
                            color: v.color,
                            stockMatrix: v.stockMatrix || {},
                            images: variantImgKeys 
                        });
                    }
                }

                const result = await db.collection('shorts').insertOne({
                    name,
                    price: parseFloat(price),
                    variants: processedVariants,
                    description,
                    createdAt: new Date()
                });
                
                return { statusCode: 201, headers, body: JSON.stringify(result) };
            }

        case 'get-shorts': {
    const shorts = await db.collection('shorts').find({}).sort({ createdAt: -1 }).toArray();

    const shortsWithLinks = await Promise.all(shorts.map(async (short) => {
        /**
         * HELPER: Extracts the actual S3 key and signs it.
         * Ensures no truncated characters or full URLs break the fresh link.
         */
        const cleanAndSign = async (input) => {
            if (!input || typeof input !== 'string') return null;

            let key = input;
            // If the DB has a full URL, extract just the key part
            if (input.includes('outflickz/')) {
                key = input.split('outflickz/')[1].split('?')[0];
            }
            
            // Remove any trailing truncation characters like '…'
            const finalKey = key.replace(/[…\s]/g, '').trim();

            // Return a fresh signed URL (valid for 12 hours)
            return await getSecureUrl(finalKey);
        };

        // 1. FALLBACK LOGIC: Identify the best image source first
        let imageToProcess = short.displayImage;
        // If no global display image exists, use the first image from the first variant
        if (!imageToProcess && short.variants?.[0]?.images?.[0]) {
            imageToProcess = short.variants[0].images[0];
        }

        // 2. SIGN THE DISPLAY IMAGE (using the helper to clean it first)
        const signedDisplay = await cleanAndSign(imageToProcess);

        // 3. SIGN ALL VARIANT IMAGES
        const signedVariants = await Promise.all((short.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(k => cleanAndSign(k)));
            // Remove any nulls if images were missing or broken
            return { ...v, images: vImgs.filter(img => img !== null) };
        }));

        return { 
            ...short, 
            displayImage: signedDisplay,
            variants: signedVariants 
        };
    }));

    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Forces frontend to get new links
        }, 
        body: JSON.stringify(shortsWithLinks) 
    };
}

            case 'get-short-details': {
                const { id } = body;
                if (!id) throw new Error("ID required");
                const product = await db.collection('shorts').findOne({ _id: new ObjectId(id) });
                if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
                
                // Sign variant images
                const signedVariants = await Promise.all((product.variants || []).map(async v => {
                    const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
                    return { ...v, images: vImgs };
                }));

                return { statusCode: 200, headers, body: JSON.stringify({ ...product, variants: signedVariants }) };
            }

            case 'update-short': {
                const { id, name, price, description, variants } = body;
                if (!id) throw new Error("ID required");

                const existing = await db.collection('shorts').findOne({ _id: new ObjectId(id) });
                if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

                const finalVariants = await Promise.all((variants || []).map(async (v) => {
                    const vImgKeys = [];
                    if (v.images && Array.isArray(v.images)) {
                        for (const img of v.images) {
                            // If it's a new base64 string, upload it
                            if (typeof img === 'string' && img.startsWith('data:')) {
                                const key = await uploadToS3(img);
                                if (key) vImgKeys.push(key);
                            } else {
                                // Keep existing key (already an S3 key)
                                vImgKeys.push(img);
                            }
                        }
                    }
                    return {
                        color: v.color,
                        stockMatrix: v.stockMatrix || {},
                        images: vImgKeys
                    };
                }));

                await db.collection('shorts').updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { name, price: parseFloat(price), description, variants: finalVariants, updatedAt: new Date() } }
                );
                
                return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
            }

            case 'delete-short': {
                const { id } = body;
                if (!id) throw new Error("ID required");
                await db.collection('shorts').deleteOne({ _id: new ObjectId(id) });
                return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
            }

        
case 'add-cap': {
    const { name, price, description, variants } = body;

    const processedVariants = [];
    if (variants && Array.isArray(variants)) {
        for (const v of variants) {
            const variantImgKeys = [];
            // Handle the array of up to 4 images
            if (v.images && Array.isArray(v.images)) {
                for (const imgBase64 of v.images) {
                    if (imgBase64) { // Ensure string isn't empty
                        const key = await uploadToS3(imgBase64);
                        if (key) variantImgKeys.push(key);
                    }
                }
            }
            processedVariants.push({
                color: v.color,
                stock: parseInt(v.stock) || 0,
                images: variantImgKeys // Stores the array of S3 keys
            });
        }
    }

    const result = await db.collection('caps').insertOne({
        name,
        price: parseFloat(price),
        variants: processedVariants,
        description,
        createdAt: new Date()
    });
    
    return { statusCode: 201, headers, body: JSON.stringify(result) };
}
case 'get-caps': {
    const caps = await db.collection('caps').find({}).sort({ createdAt: -1 }).toArray();

    const capsWithLinks = await Promise.all(caps.map(async (cap) => {
        /**
         * HELPER: Extracts the actual S3 key from a potentially broken URL.
         * This prevents the "ellipsis" truncation from breaking the signing process.
         */
        const cleanAndSign = async (input) => {
            if (!input || typeof input !== 'string') return null;

            let key = input;
            // If the DB has a full URL, extract just the part after your bucket/vault identifier
            if (input.includes('outflickz/')) {
                key = input.split('outflickz/')[1].split('?')[0];
            }
            
            // Critical: Remove any trailing truncation characters like '…' or whitespace
            const finalKey = key.replace(/[…\s]/g, '').trim();
            
            // Return a fresh signed URL from the private bucket
            return await getSecureUrl(finalKey);
        };

        // --- FALLBACK LOGIC START ---
        let imageToProcess = cap.displayImage;
        // If displayImage is missing, borrow the first image from the first variant
        if (!imageToProcess && cap.variants?.[0]?.images?.[0]) {
            imageToProcess = cap.variants[0].images[0];
        }
        // --- FALLBACK LOGIC END ---

        // 1. Sign the Global Display Image (using the identified best source)
        const signedDisplay = await cleanAndSign(imageToProcess);

        // 2. Sign all Variant Images
        const signedVariants = await Promise.all((cap.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(k => cleanAndSign(k)));
            // Filter out nulls to prevent frontend crashes
            return { ...v, images: vImgs.filter(img => img !== null) };
        }));

        return { 
            ...cap, 
            displayImage: signedDisplay,
            variants: signedVariants 
        };
    }));

    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Prevents browser from caching expired private links
        }, 
        body: JSON.stringify(capsWithLinks) 
    };
}

case 'get-cap-details': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    const product = await db.collection('caps').findOne({ _id: new ObjectId(id) });
    if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
    
    const signedVariants = await Promise.all((product.variants || []).map(async v => {
        const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
        return { ...v, images: vImgs };
    }));

    return { statusCode: 200, headers, body: JSON.stringify({ ...product, variants: signedVariants }) };
}

case 'update-cap': {
    const { id, name, price, description, variants } = body;
    if (!id) throw new Error("ID required");

    const existing = await db.collection('caps').findOne({ _id: new ObjectId(id) });
    if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

    const finalVariants = await Promise.all((variants || []).map(async (v, index) => {
        const vImgKeys = [];
        
        // Match with existing variant to preserve images if no new ones are uploaded
        const existingVariant = existing.variants && existing.variants[index];

        if (v.images && Array.isArray(v.images) && v.images.length > 0) {
            for (const img of v.images) {
                if (typeof img === 'string' && img.startsWith('data:')) {
                    // It's a new upload
                    const key = await uploadToS3(img);
                    if (key) vImgKeys.push(key);
                } else if (typeof img === 'string' && !img.startsWith('http')) {
                    // It's an existing S3 key (not a signed URL)
                    vImgKeys.push(img);
                }
            }
        } 
        
        // Fallback: If no new images were sent in the payload for this variant, 
        // keep the old ones so they aren't wiped out.
        const imagesToSave = vImgKeys.length > 0 ? vImgKeys : (existingVariant ? existingVariant.images : []);

        return {
            color: v.color,
            stock: parseInt(v.stock) || 0,
            images: imagesToSave
        };
    }));

    await db.collection('caps').updateOne(
        { _id: new ObjectId(id) },
        { 
            $set: { 
                name, 
                price: parseFloat(price), 
                description, 
                variants: finalVariants, 
                updatedAt: new Date() 
            } 
        }
    );
    
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
}

case 'delete-cap': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    await db.collection('caps').deleteOne({ _id: new ObjectId(id) });
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
}

// --- JERSEY ASSET ACTIONS ---

case 'add-jersey': {
    const { name, price, description, variants } = body;

    const processedVariants = [];
    if (variants && Array.isArray(variants)) {
        for (const v of variants) {
            const variantImgKeys = [];
            if (v.images && Array.isArray(v.images)) {
                for (const imgBase64 of v.images) {
                    const key = await uploadToS3(imgBase64);
                    if (key) variantImgKeys.push(key);
                }
            }
            processedVariants.push({
                color: v.color,
                stockMatrix: v.stockMatrix || {},
                images: variantImgKeys 
            });
        }
    }

    const result = await db.collection('jerseys').insertOne({
        name,
        price: parseFloat(price),
        variants: processedVariants,
        description,
        createdAt: new Date()
    });
    
    return { statusCode: 201, headers, body: JSON.stringify(result) };
}
case 'get-jerseys': {
    const jerseys = await db.collection('jerseys').find({}).sort({ createdAt: -1 }).toArray();

    const jerseysWithLinks = await Promise.all(jerseys.map(async (jersey) => {
        /**
         * HELPER: Extracts the raw S3 key from truncated or full URLs.
         * Ensures getSecureUrl receives a valid path like 'vault/image.webp'.
         */
        const cleanAndSign = async (input) => {
            if (!input || typeof input !== 'string') return null;

            let key = input;
            // Extract the key if the DB accidentally stored a full URL
            if (input.includes('outflickz/')) {
                key = input.split('outflickz/')[1].split('?')[0];
            }
            
            // Remove the ellipsis (…) and any whitespace causing truncation errors
            const finalKey = key.replace(/[…\s]/g, '').trim();

            // Generate a fresh 12-hour signed URL for the private bucket
            return await getSecureUrl(finalKey);
        };

        // --- NEW FALLBACK LOGIC START ---
        let imageToProcess = jersey.displayImage;
        // If displayImage is missing, use the first image from the first variant as a backup
        if (!imageToProcess && jersey.variants?.[0]?.images?.[0]) {
            imageToProcess = jersey.variants[0].images[0];
        }
        // --- NEW FALLBACK LOGIC END ---

        // 1. Sign the Primary Display Image (using the identified best source)
        const signedDisplay = await cleanAndSign(imageToProcess);

        // 2. Sign all Variant Image Arrays
        const signedVariants = await Promise.all((jersey.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(k => cleanAndSign(k)));
            // Filter out nulls to keep the data clean for the frontend
            return { ...v, images: vImgs.filter(img => img !== null) };
        }));

        return { 
            ...jersey, 
            displayImage: signedDisplay,
            variants: signedVariants 
        };
    }));

    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Prevent stale links from being cached
        }, 
        body: JSON.stringify(jerseysWithLinks) 
    };
}

case 'get-jersey-details': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    const product = await db.collection('jerseys').findOne({ _id: new ObjectId(id) });
    if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
    
    const signedVariants = await Promise.all((product.variants || []).map(async v => {
        const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
        return { ...v, images: vImgs };
    }));

    return { statusCode: 200, headers, body: JSON.stringify({ ...product, variants: signedVariants }) };
}

case 'update-jersey': {
    const { id, name, price, description, variants } = body;
    if (!id) throw new Error("ID required");

    const existing = await db.collection('jerseys').findOne({ _id: new ObjectId(id) });
    if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

    const finalVariants = await Promise.all((variants || []).map(async (v) => {
        const vImgKeys = [];
        if (v.images && Array.isArray(v.images)) {
            for (const img of v.images) {
                // If it's a new base64 string, upload it to S3
                if (typeof img === 'string' && img.startsWith('data:')) {
                    const key = await uploadToS3(img);
                    if (key) vImgKeys.push(key);
                } else {
                    // It's already a key or a URL, keep it
                    // Note: If you store full URLs, you might need to strip the domain back to a key 
                    // depending on how your getSecureUrl handles inputs.
                    vImgKeys.push(img);
                }
            }
        }
        return {
            color: v.color,
            stockMatrix: v.stockMatrix || {},
            images: vImgKeys
        };
    }));

    await db.collection('jerseys').updateOne(
        { _id: new ObjectId(id) },
        { $set: { name, price: parseFloat(price), description, variants: finalVariants, updatedAt: new Date() } }
    );
    
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
}

case 'delete-jersey': {
    const { id } = body;
    await db.collection('jerseys').deleteOne({ _id: new ObjectId(id) });
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
}

// --- TANKTOP ASSET ACTIONS ---

case 'add-tanktop': {
    const { name, price, description, variants } = body;

    const processedVariants = [];
    if (variants && Array.isArray(variants)) {
        for (const v of variants) {
            const variantImgKeys = [];
            if (v.images && Array.isArray(v.images)) {
                for (const imgBase64 of v.images) {
                    const key = await uploadToS3(imgBase64);
                    if (key) variantImgKeys.push(key);
                }
            }
            processedVariants.push({
                color: v.color,
                stockMatrix: v.stockMatrix || {},
                images: variantImgKeys 
            });
        }
    }

    const result = await db.collection('tanktops').insertOne({
        name,
        price: parseFloat(price),
        variants: processedVariants,
        description,
        createdAt: new Date()
    });
    
    return { statusCode: 201, headers, body: JSON.stringify(result) };
}
case 'get-tanktops': {
    const tanktops = await db.collection('tanktops').find({}).sort({ createdAt: -1 }).toArray();

    const tanktopsWithLinks = await Promise.all(tanktops.map(async (tanktop) => {
        /**
         * HELPER: Strips URLs and ellipsis to recover the raw S3 Key.
         * This ensures getSecureUrl receives a valid path (e.g., 'vault/file.webp').
         */
        const cleanAndSign = async (input) => {
            if (!input || typeof input !== 'string') return null;

            let key = input;
            // 1. If it's a full URL, extract the path after 'outflickz/'
            if (input.includes('outflickz/')) {
                key = input.split('outflickz/')[1].split('?')[0];
            }
            
            // 2. Remove the '…' character and any whitespace
            const finalKey = key.replace(/[…\s]/g, '').trim();

            // 3. Generate a fresh temporary link for the Private Bucket
            return await getSecureUrl(finalKey);
        };

        // --- FALLBACK LOGIC START ---
        let imageToProcess = tanktop.displayImage;
        // If main displayImage is missing, borrow the first variant's first image
        if (!imageToProcess && tanktop.variants?.[0]?.images?.[0]) {
            imageToProcess = tanktop.variants[0].images[0];
        }
        // --- FALLBACK LOGIC END ---

        // 1. Sign the Main Image (using the identified best source)
        const signedDisplay = await cleanAndSign(imageToProcess);

        // 2. Sign all Variant Images
        const signedVariants = await Promise.all((tanktop.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(k => cleanAndSign(k)));
            // Filter nulls so the frontend doesn't break
            return { ...v, images: vImgs.filter(img => img !== null) };
        }));

        return { 
            ...tanktop, 
            displayImage: signedDisplay,
            variants: signedVariants 
        };
    }));

    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Prevents old links from staying in browser memory
        }, 
        body: JSON.stringify(tanktopsWithLinks) 
    };
}

case 'get-tanktop-details': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    const product = await db.collection('tanktops').findOne({ _id: new ObjectId(id) });
    if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
    
    const signedVariants = await Promise.all((product.variants || []).map(async v => {
        const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
        return { ...v, images: vImgs };
    }));

    return { statusCode: 200, headers, body: JSON.stringify({ ...product, variants: signedVariants }) };
}

case 'update-tanktop': {
    const { id, name, price, description, variants } = body;
    if (!id) throw new Error("ID required");

    const existing = await db.collection('tanktops').findOne({ _id: new ObjectId(id) });
    if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

    const finalVariants = await Promise.all((variants || []).map(async (v) => {
        const vImgKeys = [];
        if (v.images && Array.isArray(v.images)) {
            for (const img of v.images) {
                // If new base64, upload; otherwise keep existing key
                if (typeof img === 'string' && img.startsWith('data:')) {
                    const key = await uploadToS3(img);
                    if (key) vImgKeys.push(key);
                } else {
                    vImgKeys.push(img);
                }
            }
        }
        return {
            color: v.color,
            stockMatrix: v.stockMatrix || {},
            images: vImgKeys
        };
    }));

    await db.collection('tanktops').updateOne(
        { _id: new ObjectId(id) },
        { $set: { 
            name, 
            price: parseFloat(price), 
            description, 
            variants: finalVariants, 
            updatedAt: new Date() 
        } }
    );
    
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
}

case 'delete-tanktop': {
    const { id } = body;
    await db.collection('tanktops').deleteOne({ _id: new ObjectId(id) });
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
}

// --- TRACKSUIT HANDLERS ---

case 'add-tracksuit': {
    const { name, price, description, variants } = body;

    const processedVariants = [];
    if (variants && Array.isArray(variants)) {
        for (const v of variants) {
            const variantImgKeys = [];
            if (v.images && Array.isArray(v.images)) {
                for (const imgBase64 of v.images) {
                    // Uploads each base64 image string to S3 and gets a key
                    const key = await uploadToS3(imgBase64);
                    if (key) variantImgKeys.push(key);
                }
            }
            processedVariants.push({
                color: v.color,
                stockMatrix: v.stockMatrix || {},
                images: variantImgKeys 
            });
        }
    }

    const result = await db.collection('tracksuits').insertOne({
        name,
        price: parseFloat(price),
        variants: processedVariants,
        description,
        createdAt: new Date()
    });
    
    return { statusCode: 201, headers, body: JSON.stringify(result) };
}
case 'get-tracksuits': {
    const tracksuits = await db.collection('tracksuits').find({}).sort({ createdAt: -1 }).toArray();
    
    const tracksuitsWithLinks = await Promise.all(tracksuits.map(async (t) => {
        /**
         * HELPER: Extracts the raw S3 key from truncated or full URLs.
         * Resolves the "ellipsis" issue by stripping garbage characters.
         */
        const cleanAndSign = async (input) => {
            if (!input || typeof input !== 'string') return null;

            let key = input;
            // 1. If the DB contains a full URL, extract the part after your bucket identifier
            if (input.includes('outflickz/')) {
                key = input.split('outflickz/')[1].split('?')[0];
            }
            
            // 2. Critical: Strip the truncation ellipsis (…) and any stray whitespace
            const finalKey = key.replace(/[…\s]/g, '').trim();

            // 3. Generate the 12-hour temporary link for the Private Bucket
            return await getSecureUrl(finalKey);
        };

        // --- FALLBACK LOGIC START ---
        let imageToProcess = t.displayImage;
        // If main displayImage is missing, use the first image from the first variant as a backup
        if (!imageToProcess && t.variants?.[0]?.images?.[0]) {
            imageToProcess = t.variants[0].images[0];
        }
        // --- FALLBACK LOGIC END ---

        // 1. Sign the Primary Display Image (using cleaned fallback if necessary)
        const signedDisplay = await cleanAndSign(imageToProcess);

        // 2. Sign all Variant Images
        const signedVariants = await Promise.all((t.variants || []).map(async v => {
            const vImgs = await Promise.all((v.images || []).map(k => cleanAndSign(k)));
            // Filter out nulls to keep frontend arrays clean
            return { ...v, images: vImgs.filter(img => img !== null) };
        }));

        return { 
            ...t, 
            displayImage: signedDisplay,
            variants: signedVariants 
        };
    }));
    
    return { 
        statusCode: 200, 
        headers: {
            ...headers,
            'Cache-Control': 'no-cache, no-store, must-revalidate' // Forces fresh links on every request
        }, 
        body: JSON.stringify(tracksuitsWithLinks) 
    };
}

case 'get-tracksuit-details': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    const product = await db.collection('tracksuits').findOne({ _id: new ObjectId(id) });
    if (!product) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };
    
    const signedVariants = await Promise.all((product.variants || []).map(async v => {
        const vImgs = await Promise.all((v.images || []).map(k => getSecureUrl(k)));
        return { ...v, images: vImgs };
    }));

    return { statusCode: 200, headers, body: JSON.stringify({ ...product, variants: signedVariants }) };
}

case 'update-tracksuit': {
    const { id, name, price, description, variants } = body;
    if (!id) throw new Error("ID required");

    const existing = await db.collection('tracksuits').findOne({ _id: new ObjectId(id) });
    if (!existing) return { statusCode: 404, headers, body: JSON.stringify({ message: "Not found" }) };

    const finalVariants = await Promise.all((variants || []).map(async (v) => {
        const vImgKeys = [];
        if (v.images && Array.isArray(v.images)) {
            for (const img of v.images) {
                // If it's a new base64 string (from file upload), upload to S3
                if (typeof img === 'string' && img.startsWith('data:')) {
                    const key = await uploadToS3(img);
                    if (key) vImgKeys.push(key);
                } else {
                    // If it's already a key (not a base64), keep it as is
                    // This handles cases where images weren't changed during edit
                    const cleanKey = typeof img === 'string' && img.includes('?') ? img.split('?')[0].split('/').pop() : img;
                    vImgKeys.push(cleanKey);
                }
            }
        }
        return {
            color: v.color,
            stockMatrix: v.stockMatrix || {},
            images: vImgKeys
        };
    }));

    await db.collection('tracksuits').updateOne(
        { _id: new ObjectId(id) },
        { $set: { name, price: parseFloat(price), description, variants: finalVariants, updatedAt: new Date() } }
    );
    
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Success" }) };
}

case 'delete-tracksuit': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    await db.collection('tracksuits').deleteOne({ _id: new ObjectId(id) });
    return { statusCode: 200, headers, body: JSON.stringify({ message: "Removed" }) };
}

            case 'admin-register': {
                const { firstName, lastName, email, password, masterKey } = body;
                if (!masterKey || masterKey.trim() !== MASTER_ACCESS_KEY) {
                    return { statusCode: 403, headers, body: JSON.stringify({ message: "Security Refusal" }) };
                }
                const hashedPassword = await bcrypt.hash(password, 10);
                await db.collection('admins').insertOne({
                    firstName, lastName, email: email.toLowerCase().trim(),
                    password: hashedPassword, role: 'admin', createdAt: new Date()
                });
                return { statusCode: 201, headers, body: JSON.stringify({ message: "Admin created" }) };
            }

            case 'admin-login': {
                const { email, password, masterKey } = body;
                if (!masterKey || masterKey.trim() !== MASTER_ACCESS_KEY) {
                    return { statusCode: 403, headers, body: JSON.stringify({ message: "Invalid Secret" }) };
                }
                const admin = await db.collection('admins').findOne({ email: email.toLowerCase().trim() });
                if (!admin || !(await bcrypt.compare(password, admin.password))) {
                    return { statusCode: 401, headers, body: JSON.stringify({ message: "Unauthorized" }) };
                }
                const token = jwt.sign({ id: admin._id, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
                return { statusCode: 200, headers, body: JSON.stringify({ token, admin: { firstName: admin.firstName } }) };
            }

            case 'admin-reset-password': {
    const { email, masterKey, newPassword } = body;
    const MASTER_SECRET = "Outflickzlimited"; // Your master key

    if (!email || !masterKey || !newPassword) {
        throw new Error("All security parameters required");
    }

    if (masterKey !== MASTER_SECRET) {
        return { statusCode: 403, headers, body: JSON.stringify({ message: "Invalid Master Secret Key" }) };
    }

    // Hash the new password (assuming you use a helper or plain text for now as per previous snippets)
    const updateResult = await db.collection('admins').updateOne(
        { email: email.toLowerCase() },
        { $set: { password: newPassword } }
    );

    if (updateResult.matchedCount === 0) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "Admin profile not found" }) };
    }

    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify({ success: true, message: "Credentials updated successfully" }) 
    };
}

// --- CASE 1: FETCH PROFILE DETAILS ---
case 'get-admin-profile': {
    const { token, masterKey } = body;

    // Verify Master Key
    if (!masterKey || masterKey !== "Outflickzlimited") {
        return { statusCode: 403, headers, body: JSON.stringify({ message: "Invalid Master Secret" }) };
    }

    try {
        // Decode the JWT token to get the Admin ID
        const decoded = jwt.verify(token, JWT_SECRET);
        const admin = await db.collection('admins').findOne({ _id: new ObjectId(decoded.id) });

        if (!admin) {
            return { statusCode: 404, headers, body: JSON.stringify({ success: false, message: "Admin not found" }) };
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                admin: {
                    name: admin.firstName + " " + (admin.lastName || ""),
                    email: admin.email
                }
            })
        };
    } catch (err) {
        return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: "Session Expired" }) };
    }
}

// --- CASE 2: SECURE PASSWORD UPDATE ---
case 'update-admin-password': {
    const { token, newPassword, masterKey } = body;
    const MASTER_SECRET = "Outflickzlimited";

    // 1. Validate Master Key
    if (!masterKey || masterKey !== MASTER_SECRET) {
        return { statusCode: 403, headers, body: JSON.stringify({ message: "Invalid Master Secret Key" }) };
    }

    try {
        // 2. Verify current session
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 3. Hash the new password (Security Priority)
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // 4. Update the database
        const updateResult = await db.collection('admins').updateOne(
            { _id: new ObjectId(decoded.id) },
            { $set: { password: hashedPassword } }
        );

        if (updateResult.matchedCount === 0) {
            return { statusCode: 404, headers, body: JSON.stringify({ message: "Admin profile not found" }) };
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, message: "Vault credentials updated successfully" }) 
        };
    } catch (err) {
        return { statusCode: 401, headers, body: JSON.stringify({ success: false, message: "Session Invalid" }) };
    }
}
case 'get-dashboard': {
    try {
        const now = new Date();
        const startOfToday = new Date(now);
        startOfToday.setHours(0, 0, 0, 0);
        
        const startOfWeek = new Date(now);
        startOfWeek.setDate(now.getDate() - 7);

        // Helper to get both Unit Count and Financial Value (Stock * Price)
        const getCollectionMetrics = async (colName) => {
            const result = await db.collection(colName).aggregate([
                { $unwind: "$variants" },
                {
                    $project: {
                        price: { $toDouble: { $ifNull: ["$price", 0] } },
                        variantTotal: {
                            $cond: {
                                if: { $gt: [{ $size: { $objectToArray: { $ifNull: ["$variants.stockMatrix", {}] } } }, 0] },
                                then: { $sum: { $map: { input: { $objectToArray: "$variants.stockMatrix" }, as: "kv", in: { $toInt: "$$kv.v" } } } },
                                else: { $toInt: { $ifNull: ["$variants.stock", 0] } }
                            }
                        }
                    }
                },
                { 
                    $group: { 
                        _id: null, 
                        totalStock: { $sum: "$variantTotal" },
                        totalValue: { $sum: { $multiply: ["$variantTotal", "$price"] } }
                    } 
                }
            ]).toArray();
            
            return {
                units: result[0]?.totalStock || 0,
                value: result[0]?.totalValue || 0
            };
        };

        const [
            wears, shorts, caps, jerseys, tanktops, tracksuits,
            revenueMetrics, weeklyAgg, monthlyAgg, dailyAgg
        ] = await Promise.all([
            getCollectionMetrics('wears'), getCollectionMetrics('shorts'), getCollectionMetrics('caps'),
            getCollectionMetrics('jerseys'), getCollectionMetrics('tanktops'), getCollectionMetrics('tracksuits'),
            
            // UPDATED: Aggregating Revenue, Shipping, and Tax separately
            db.collection('orders').aggregate([
                { $match: { status: 'Confirmed' } },
                { 
                    $group: { 
                        _id: null, 
                        totalGross: { $sum: { $toDouble: "$amountPaid" } }, 
                        totalShipping: { $sum: { $toDouble: { $ifNull: ["$shippingFee", 0] } } },
                        totalTax: { $sum: { $toDouble: { $ifNull: ["$taxAmount", 0] } } } 
                    } 
                }
            ]).toArray(),

            db.collection('orders').aggregate([
                { $match: { status: 'Confirmed', createdAt: { $gte: startOfWeek } } },
                { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, dailyTotal: { $sum: "$amountPaid" } } },
                { $sort: { "_id": 1 } }
            ]).toArray(),

            db.collection('orders').aggregate([
                { $match: { status: 'Confirmed' } },
                { $group: { _id: { $dateToString: { format: "%Y-%m", date: "$createdAt" } }, monthTotal: { $sum: "$amountPaid" } } },
                { $sort: { "_id": -1 } },
                { $limit: 6 }
            ]).toArray(),

            db.collection('orders').aggregate([
                { $match: { status: 'Confirmed', createdAt: { $gte: startOfToday } } },
                { $group: { _id: { $hour: "$createdAt" }, total: { $sum: "$amountPaid" } } }
            ]).toArray()
        ]);

        // Aggregate Totals
        const totalUnits = wears.units + shorts.units + caps.units + jerseys.units + tanktops.units + tracksuits.units;
        const totalInventoryValue = wears.value + shorts.value + caps.value + jerseys.value + tanktops.value + tracksuits.value;

        // Daily formatting (4-hour chunks)
        const dailyLabels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
        const dailyValues = dailyLabels.map((_, i) => {
            const h = i * 4;
            return dailyAgg.filter(it => it._id >= h && it._id < h + 4).reduce((s, it) => s + it.total, 0);
        });

        // Weekly formatting
        const weeklyValues = [];
        const weeklyLabels = [];
        for (let i = 6; i >= 0; i--) {
            const d = new Date(); d.setDate(d.getDate() - i);
            const ds = d.toISOString().split('T')[0];
            const m = weeklyAgg.find(it => it._id === ds);
            weeklyLabels.push(d.toLocaleDateString('en-US', { weekday: 'short' }));
            weeklyValues.push(m ? m.dailyTotal : 0);
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                success: true,
                stats: { 
                    revenue: revenueMetrics[0]?.totalGross || 0, 
                    totalShipping: revenueMetrics[0]?.totalShipping || 0,
                    totalTax: revenueMetrics[0]?.totalTax || 0,
                    totalStockValue: totalInventoryValue,
                    allTotalProducts: totalUnits,
                    wears: wears.units, 
                    shorts: shorts.units, 
                    caps: caps.units, 
                    jerseys: jerseys.units, 
                    tanktops: tanktops.units, 
                    tracksuits: tracksuits.units 
                },
                salesData: {
                    daily: { labels: dailyLabels, values: dailyValues },
                    weekly: { labels: weeklyLabels, values: weeklyValues },
                    monthly: { labels: ['Wk 1', 'Wk 2', 'Wk 3', 'Current'], values: [0, 0, 0, weeklyValues.reduce((a,b)=>a+b, 0)] },
                    yearly: { labels: monthlyAgg.map(m => m._id).reverse(), values: monthlyAgg.map(m => m.monthTotal).reverse() }
                }
            }) 
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}

case 'get-all-inventory': {
    try {
        const collections = ['wears', 'shorts', 'caps', 'jerseys', 'tanktops', 'tracksuits'];
        let allProducts = [];
        let grandTotalValue = 0;

        for (const col of collections) {
            const products = await db.collection(col).find({}).toArray();
            
            products.forEach(p => {
                let productUnits = 0;
                // Calculate stock from variants/stockMatrix
                if (p.variants) {
                    p.variants.forEach(v => {
                        if (v.stockMatrix) {
                            productUnits += Object.values(v.stockMatrix).reduce((a, b) => a + parseInt(b || 0), 0);
                        } else {
                            productUnits += parseInt(v.stock || 0);
                        }
                    });
                }

                const price = parseFloat(p.price || 0);
                allProducts.push({
                    category: col,
                    name: p.name,
                    price: price,
                    totalStock: productUnits
                });
                grandTotalValue += (price * productUnits);
            });
        }

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                products: allProducts,
                totalValue: grandTotalValue
            })
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}
   case 'add-social-post': {
    const { postUrl, manualImageUrl } = body;
    if (!postUrl) return { statusCode: 400, headers, body: JSON.stringify({ message: "URL required" }) };

    try {
        let cleanUrl = postUrl.split('?')[0];
        if (!cleanUrl.endsWith('/')) cleanUrl += '/';
        
        // If manualImageUrl exists, use it. Otherwise, use the Instagram media trick.
        const finalImageUrl = manualImageUrl ? manualImageUrl : `${cleanUrl}media/?size=l`;

        const newPost = {
            imageUrl: finalImageUrl, 
            postUrl: cleanUrl,
            createdAt: new Date()
        };

        await db.collection('social_gallery').insertOne(newPost);
        return { statusCode: 201, headers, body: JSON.stringify({ message: "Synced" }) };
    } catch (error) {
        return { statusCode: 500, headers, body: JSON.stringify({ error: error.message }) };
    }
}

// 2. FETCH ALL POSTS (No changes needed, but kept for consistency)
case 'get-social-gallery': {
    const posts = await db.collection('social_gallery')
        .find({})
        .sort({ createdAt: -1 })
        .toArray();

    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify(posts) 
    };
}

// 3. DELETE A POST
case 'delete-social-post': {
    const { id } = body;
    
    if (!id) {
        return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ message: "ID required for deletion" }) 
        };
    }

    // Import ObjectId within the case or at the top of your function file
    const { ObjectId } = require('mongodb'); 
    
    try {
        await db.collection('social_gallery').deleteOne({ _id: new ObjectId(id) });
        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ message: "Post removed" }) 
        };
    } catch (error) {
        return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ message: "Invalid ID format" }) 
        };
    }
}

case 'get-any-product-details': {
    const { id } = body;
    if (!id) throw new Error("ID required");
    
    const collections = ['wears', 'shorts', 'caps', 'jerseys', 'tanktops', 'tracksuits'];
    let product = null;
    let foundCollection = '';

    for (const col of collections) {
        // Ensure id is a valid ObjectId before searching
        try {
            product = await db.collection(col).findOne({ _id: new ObjectId(id) });
            if (product) {
                foundCollection = col;
                break; 
            }
        } catch (oidErr) {
            continue; // Skip if ID format is invalid for this collection
        }
    }

    if (!product) {
        return { statusCode: 404, headers, body: JSON.stringify({ message: "Product not found" }) };
    }

    // 1. SIGN TOP-LEVEL PRODUCT IMAGES (Optional, but safe)
    if (product.images && Array.isArray(product.images)) {
        product.images = await Promise.all(product.images.map(k => getSecureUrl(k)));
    }

    // 2. SIGN VARIANT IMAGES
    const signedVariants = await Promise.all((product.variants || []).map(async v => {
        let signedVImgs = [];
        if (v.images && Array.isArray(v.images)) {
            // Sign each key in the variant's image array
            signedVImgs = await Promise.all(v.images.map(k => getSecureUrl(k)));
        }
        return { ...v, images: signedVImgs };
    }));

    // 3. RETURN DATA WITH CATEGORY
    return { 
        statusCode: 200, 
        headers, 
        body: JSON.stringify({ 
            ...product, 
            variants: signedVariants,
            category: foundCollection // Critical for the "Fitment" vs "Size" label logic
        }) 
    };
}

case 'get-all-products-combined': {
    // Fetch all collections in parallel for maximum speed
    const [wears, shorts, caps, jerseys, tracksuits, tanktops] = await Promise.all([
        db.collection('wears').find({}).toArray(),
        db.collection('shorts').find({}).toArray(),
        db.collection('caps').find({}).toArray(),
        db.collection('jerseys').find({}).toArray(),
        db.collection('tracksuits').find({}).toArray(),
        db.collection('tanktops').find({}).toArray()
    ]);

    // Combine them and label them so the frontend knows what is what
    const allProducts = [
        ...wears.map(p => ({ ...p, category: 'wear' })),
        ...shorts.map(p => ({ ...p, category: 'short' })),
        ...caps.map(p => ({ ...p, category: 'cap' })),
        ...jerseys.map(p => ({ ...p, category: 'jersey' })),
        ...tracksuits.map(p => ({ ...p, category: 'tracksuit' })),
        ...tanktops.map(p => ({ ...p, category: 'tanktop' }))
    ];

    // Sign the first image of each product for the slider preview
    const signedProducts = await Promise.all(allProducts.map(async (p) => {
        // Get the first image of the first variant
        const firstKey = p.variants?.[0]?.images?.[0];
        const signedUrl = firstKey ? await getSecureUrl(firstKey) : null;
        return { ...p, displayImage: signedUrl };
    }));

    return { statusCode: 200, headers, body: JSON.stringify(signedProducts) };
}


async function processOrderDeduction(db, reference, orderData, paymentData, method) {
    const { ObjectId } = require('mongodb');

    // 1. Idempotency Check (Prevent double processing)
    const existingOrder = await db.collection('orders').findOne({ paymentReference: reference });
    if (existingOrder) return { success: true, message: "Already processed", orderId: existingOrder._id };

    // 2. Prepare Order Document
    const orderDoc = {
        ...orderData,
        // FIX: Ensure email exists. Check orderData first, then Paystack customer data
        email: orderData.email || paymentData.customer?.email || null,
        paymentReference: reference,
        paymentMode: `paystack_${paymentData.channel || 'other'}`,
        status: 'Confirmed',
        paymentStatus: 'Paid',
        pickupLocation: orderData.deliveryMethod === 'pickup' ? orderData.pickupLocation : null,
        gatewayResponse: paymentData.gateway_response,
        amountPaid: (paymentData.amount / 100),
        paidAt: paymentData.paid_at ? new Date(paymentData.paid_at) : new Date(),
        createdAt: new Date(),
        processedVia: method,
        reference: reference
    };

    // 3. Save Order & Capture ID
    const orderResult = await db.collection('orders').insertOne(orderDoc);
    orderDoc._id = orderResult.insertedId;
// 4. Email Dispatch (Wait and Verify)
if (orderDoc.email) {
    console.log(`INITIATING_EMAIL_DISPATCH: Sending to ${orderDoc.email}`);
    
    // We MUST await here so Netlify doesn't kill the function early
    try {
        await sendOrderEmails(orderDoc);
        console.log("EMAIL_DISPATCH_SUCCESSFUL");
    } catch (err) {
        // If email fails, we still want the order to be processed, so we just log the error
        console.error("BLOCKING_EMAIL_FAILURE:", err.message);
    }
} else {
    console.warn("EMAIL_SKIPPED: No email address found for reference:", reference);
}

    // 5. Inventory Deduction Logic
    const inventoryUpdates = (orderData.items || []).map(async (item) => {
        const collectionMap = {
            'wear': 'wears', 'wears': 'wears',
            'short': 'shorts', 'shorts': 'shorts',
            'cap': 'caps', 'caps': 'caps',
            'jersey': 'jerseys', 'jerseys': 'jerseys',
            'tracksuit': 'tracksuits', 'tracksuits': 'tracksuits',
            'tanktop': 'tanktops'
        };

        const category = (item.category || 'wear').toLowerCase().trim();
        const collectionName = collectionMap[category] || (category.endsWith('s') ? category : category + 's');
        
        const rawId = item._id || item.id;
        if (!rawId) return { error: "Missing ID", itemName: item.name };

        const qtyToDeduct = -Math.abs(Number(item.qty || item.quantity || 1));
        
        console.log(`Deducting: ${item.name} (${item.size || 'No Size'}) from ${collectionName}`);

        let filter = { _id: new ObjectId(rawId) };
        let update = {};
        let options = { arrayFilters: [{ "v.color": item.color }] };

        const hasSize = item.size && !['One Size', '', 'OS', 'N/A'].includes(item.size);

        // Filter variants to match the specific color
        filter["variants"] = { 
            $elemMatch: { color: item.color } 
        };

        if (hasSize) {
            update = { 
                $inc: { [`variants.$[v].stockMatrix.${item.size}`]: qtyToDeduct } 
            };
        } else {
            update = { 
                $inc: { "variants.$[v].stock": qtyToDeduct } 
            };
        }

        try {
            const res = await db.collection(collectionName).updateOne(filter, update, options);
            
            if (res.modifiedCount === 0) {
                console.error(`FAILED_DEDUCTION: No match for ${item.name}. Ref: ${rawId} | Color: ${item.color}`);
                return { name: item.name, success: false };
            }
            
            return { name: item.name, success: true };
        } catch (dbErr) {
            console.error(`DB_UPDATE_ERROR for ${item.name}:`, dbErr.message);
            return { name: item.name, success: false };
        }
    });

    const results = await Promise.all(inventoryUpdates);
    
    return { 
        success: true, 
        orderId: orderResult.insertedId, 
        results,
        emailStatus: orderDoc.email ? 'Sent to Queue' : 'No Email Found'
    };
}

case 'webhook': {
    const secret = process.env.PAYSTACK_SECRET_KEY;
    const hash = crypto.createHmac('sha512', secret)
                       .update(JSON.stringify(body))
                       .digest('hex');

    if (hash !== event.headers['x-paystack-signature']) {
        return { statusCode: 401, body: "Unauthorized" };
    }

    if (body.event === 'charge.success') {
        const orderData = body.data.metadata?.orderData;
        if (orderData) {
            await processOrderDeduction(db, body.data.reference, orderData, body.data, 'webhook');
        }
    }
    return { statusCode: 200, body: JSON.stringify({ received: true }) };
}
case 'verify-payment': {
    const { reference, orderData } = body;
    if (!reference || !orderData) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Missing data" }) };
    }

    try {
        const paystackUrl = `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`;
        const response = await fetch(paystackUrl, {
            method: 'GET',
            headers: { 
                Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`, 
                "Content-Type": "application/json" 
            }
        });

        const paymentStatus = await response.json();

        if (paymentStatus.status && paymentStatus.data.status === 'success') {
            const amountPaidKobo = paymentStatus.data.amount; 
            
            let subtotalNaira = 0;
            const collectionMap = {
                'wear': 'wears', 'short': 'shorts', 'cap': 'caps',
                'jersey': 'jerseys', 'tracksuit': 'tracksuits', 'tanktop': 'tanktops'
            };

            // 1. Calculate Subtotal from Database (Source of Truth)
            for (const item of orderData.items) {
                const category = (item.category || 'wear').toLowerCase().trim();
                const collectionName = collectionMap[category] || (category.endsWith('s') ? category : category + 's');
                const productId = item._id || item.id;
                const dbProduct = await db.collection(collectionName).findOne({ _id: new ObjectId(productId) });
                
                if (!dbProduct) {
                    return { statusCode: 400, headers, body: JSON.stringify({ message: `Product ${item.name} not found.` }) };
                }

                subtotalNaira += Number(dbProduct.price) * Number(item.qty || item.quantity);
            }

            // 2. Determine Shipping Fee
            const shippingNaira = orderData.deliveryMethod === 'pickup' 
                ? 0 
                : (Number(orderData.shippingFee) || 0);

            // 3. --- FIX: Backend calculates tax independently ---
            // We use 0.03 to match your frontend TAX_RATE
            const taxNaira = subtotalNaira * 0.03;
            
            // 4. Update the orderData object before it goes to the DB
            // This ensures the database and emails show the correct tax amount
            orderData.taxAmount = taxNaira;

            // 5. Convert all to Kobo for precise comparison
            const subtotalKobo = Math.round(subtotalNaira * 100);
            const shippingKobo = Math.round(shippingNaira * 100);
            const taxKobo = Math.round(taxNaira * 100);
            
            const expectedTotalKobo = subtotalKobo + shippingKobo + taxKobo;

            // Debugging
            console.log(`[VERIFY] Ref: ${reference}`);
            console.log(`[VERIFY] Paid (Paystack): ${amountPaidKobo}`);
            console.log(`[VERIFY] Vault Expected: ${expectedTotalKobo} (Sub:${subtotalKobo} + Ship:${shippingKobo} + Tax:${taxKobo})`);

            // Allow for minor rounding differences (50 Kobo)
            const difference = Math.abs(amountPaidKobo - expectedTotalKobo);
            
            if (difference > 50) { 
                return { 
                    statusCode: 400, 
                    headers, 
                    body: JSON.stringify({ 
                        success: false,
                        message: "Price mismatch. Payment does not match vault calculation.",
                        received: amountPaidKobo / 100,
                        expected: expectedTotalKobo / 100
                    }) 
                };
            }

            // If match, proceed to save order and deduct stock
            // We pass the modified orderData (now with taxAmount) to the deduction process
            const result = await processOrderDeduction(db, reference, orderData, paymentStatus.data, 'client_verify');
            return { statusCode: 200, headers, body: JSON.stringify(result) };
        }
        
        return { statusCode: 400, headers, body: JSON.stringify({ message: "Payment verification failed." }) };
        
    } catch (error) {
        console.error("Vault Error:", error);
        return { statusCode: 500, headers, body: JSON.stringify({ message: error.message }) };
    }
}

case 'get-orders': {
    try {
        const orders = await db.collection('orders')
            .find({})
            .sort({ createdAt: -1 })
            .toArray();

        const signedOrders = await Promise.all((orders || []).map(async (order) => {
            // 1. Standardize Financials (Consolidating all possible naming variants)
            order.shippingFee = Number(order.shippingFee || order.shippingCost || 0);
            order.taxAmount = Number(order.taxAmount || order.tax || 0);
            
            // Calculate subtotal using 'qty' (primary) or 'quantity' (fallback)
            const calcSubtotal = order.items?.reduce((acc, item) => {
                const price = Number(item.price || 0);
                const quantity = Number(item.qty || item.quantity || 1);
                return acc + (price * quantity);
            }, 0) || 0;

            order.subtotal = Number(order.subtotal || calcSubtotal);

            // Total Amount logic: Use amountPaid if exists, otherwise sum the parts
            order.totalAmount = Number(
                order.amountPaid || 
                order.totalAmount || 
                (order.subtotal + order.shippingFee + order.taxAmount)
            );
            
            // 2. Process Items (Standardizing keys for the Frontend)
            if (order.items && Array.isArray(order.items)) {
                order.items = await Promise.all(order.items.map(async (item) => {
                    // Standardize Size & Qty so Frontend always finds them
                    item.displaySize = item.size || item.selectedSize || 'OS';
                    item.displayQty = item.qty || item.quantity || 1;

                    // Handle Image Signing
                    if (item.image && typeof item.image === 'string') {
                        // If it's a raw S3 key (not a full URL), sign it
                        if (!item.image.startsWith('http')) {
                            try {
                                item.image = await getSecureUrl(item.image);
                            } catch (s3Err) {
                                console.error(`Signing failed for ${item.image}`);
                                item.image = 'https://placehold.co/400x500?text=SIGN+ERROR';
                            }
                        }
                    } else if (!item.image) {
                        item.image = 'https://placehold.co/400x500?text=NO+IMAGE';
                    }
                    return item;
                }));
            }
            return order;
        }));

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify(signedOrders)
        };
    } catch (error) {
        console.error("GET_ORDERS_ERROR:", error);
        return {
            statusCode: 500,
            headers,
            body: JSON.stringify({ 
                message: "Vault retrieval failed", 
                error: error.message 
            })
        };
    }
}

case 'update-order-status': {
    const { id, newStatus } = body;
    if (!id || !newStatus) {
        return { 
            statusCode: 400, 
            headers, 
            body: JSON.stringify({ message: "Order ID and status required" }) 
        };
    }

    try {
        // We use $set to ensure financial fields like taxAmount and shippingFee stay intact
        const result = await db.collection('orders').findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: { fulfillmentStatus: newStatus, updatedAt: new Date() } },
            { returnDocument: 'after' } 
        );

        // Safety check for different MongoDB Driver versions
        const updatedOrder = result.value || result;

        if (!updatedOrder || (result.ok === 0)) {
            return { 
                statusCode: 404, 
                headers, 
                body: JSON.stringify({ message: "Order not found or update failed" }) 
            };
        }

        // Trigger the dynamic email logic (Shipped vs Delivered)
        if (updatedOrder.email) {
            console.log(`INITIATING_STATUS_EMAIL: ${newStatus} for ${updatedOrder.email}`);
            
            // We pass the full updatedOrder so sendOrderEmails has access to 
            // the shippingAddress, tax, and item list for the template.
            await sendOrderEmails(updatedOrder, newStatus).catch(err => 
                console.error("ADMIN_ACTION_EMAIL_FAILURE:", err.message)
            );
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                success: true, 
                message: `Order marked as ${newStatus} and email queued.`,
                order: updatedOrder 
            }) 
        };
    } catch (error) {
        console.error("UPDATE_ORDER_ERROR:", error);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ message: "Failed to update order", error: error.message }) 
        };
    }
}

case 'user-request-otp': {
    const { email, firstName } = JSON.parse(event.body);
    const cleanEmail = email.toLowerCase().trim();

    // Check if user exists
    const existingUser = await db.collection('users').findOne({ email: cleanEmail });
    if (existingUser) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "EMAIL ALREADY REGISTERED" }) };
    }

    // Generate 6-digit OTP & Expiry (10 mins)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60000);

    // Store OTP in a temporary collection
    await db.collection('otp_verifications').updateOne(
        { email: cleanEmail },
        { $set: { otp, expiresAt, firstName } },
        { upsert: true }
    );

    await sendVerificationEmail(cleanEmail, otp, firstName);

    return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: "OTP SENT" }) };
}

// --- 2. VERIFY & CREATE ACCOUNT ---
case 'user-register-verify': {
    const { firstName, lastName, email, phone, shipping, password, otp } = JSON.parse(event.body);
    const cleanEmail = email.toLowerCase().trim();

    // Check OTP record
    const record = await db.collection('otp_verifications').findOne({ email: cleanEmail });
    
    if (!record || record.otp !== otp) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "INVALID OTP" }) };
    }
    if (new Date() > record.expiresAt) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "OTP EXPIRED" }) };
    }

    // Everything is valid -> Save User
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        firstName, lastName, phone, shipping,
        email: cleanEmail,
        password: hashedPassword,
        role: 'customer',
        createdAt: new Date()
    };

    await db.collection('users').insertOne(newUser);
    await db.collection('otp_verifications').deleteOne({ email: cleanEmail }); // Cleanup

    return { statusCode: 201, headers, body: JSON.stringify({ success: true, message: "ACCOUNT CREATED" }) };
}

// --- USER LOGIN ---
case 'user-login': {
    const { email, password } = JSON.parse(event.body);

    const user = await db.collection('users').findOne({ email: email.toLowerCase().trim() });
    if (!user) {
        return { 
            statusCode: 401, headers, 
            body: JSON.stringify({ success: false, message: "INVALID CREDENTIALS" }) 
        };
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return { 
            statusCode: 401, headers, 
            body: JSON.stringify({ success: false, message: "INVALID CREDENTIALS" }) 
        };
    }

    const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        JWT_SECRET,
        { expiresIn: '7d' }
    );

    return { 
        statusCode: 200, headers, 
        body: JSON.stringify({ 
            success: true, 
            message: "LOGIN SUCCESSFUL",
            token, 
            user: { 
                firstName: user.firstName, 
                lastName: user.lastName,
                email: user.email 
            } 
        }) 
    };
}
           
         case 'get-user-vault': {
    const body = JSON.parse(event.body || "{}");
    const { token } = body;
    if (!token) return { statusCode: 401, headers, body: JSON.stringify({ message: "NO SESSION" }) };

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || JWT_SECRET);
        const user = await db.collection('users').findOne(
            { _id: new ObjectId(decoded.userId) }, 
            { projection: { password: 0 } }
        );
        
        if (!user) return { statusCode: 404, headers, body: JSON.stringify({ message: "USER NOT FOUND" }) };

        // Fetch orders linked to this user's email
        const orders = await db.collection('orders')
            .find({ email: user.email })
            .sort({ createdAt: -1 })
            .toArray();

        // --- OPTIMIZED IMAGE SIGNING LOGIC ---
        // We use Promise.all on the orders, and another Promise.all on the items
        const signedOrders = await Promise.all(orders.map(async (order) => {
            if (order.items && Array.isArray(order.items)) {
                const signedItems = await Promise.all(order.items.map(async (item) => {
                    // Only sign if there is an image key and it's not already a full URL
                    if (item.image && !item.image.startsWith('http')) {
                        try {
                            // Using your helper: getSecureUrl(key)
                            item.image = await getSecureUrl(item.image);
                        } catch (err) {
                            console.error(`Signing failed for ${item.image}:`, err);
                            // Fallback to a placeholder if signing fails
                            item.image = 'https://placehold.co/400x500?text=VAULT+IMAGE';
                        }
                    }
                    return item;
                }));
                order.items = signedItems;
            }
            return order;
        }));

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ 
                success: true, 
                user, 
                orders: signedOrders 
            }) 
        };
    } catch (err) {
        console.error("Vault Error:", err);
        return { statusCode: 401, headers, body: JSON.stringify({ message: "SESSION EXPIRED" }) };
    }
}

case 'get-order-details': {
    const body = JSON.parse(event.body || "{}");
    const { orderId } = body; 
    
    try {
        const order = await db.collection('orders').findOne({ 
            $or: [
                { paymentReference: orderId },
                { reference: orderId },
                { trxref: orderId } // Added trxref for broader compatibility
            ]
        });
        
        if (order) {
            // --- CLEAN DATA TYPES ---
            // Ensure financial fields are numbers so frontend calculations don't fail
            order.amountPaid = Number(order.amountPaid || 0);
            order.shippingFee = Number(order.shippingFee || 0);
            order.taxAmount = Number(order.taxAmount || 0);
            order.taxRate = Number(order.taxRate || 0);

            // --- PROCESS IMAGE URLS ---
            // Process all items in parallel to generate secure signed URLs
            order.items = await Promise.all((order.items || []).map(async (item) => {
                // Ensure item price is a number
                item.price = Number(item.price || 0);
                
                // If item.image is a key (not a full URL), generate a secure link
                if (item.image && !item.image.startsWith('http')) {
                    try {
                        item.image = await getSecureUrl(item.image);
                    } catch (s3Error) {
                        console.error("S3 Signing Error for item:", item.name, s3Error);
                        item.image = 'https://placehold.co/300x400?text=Image+Unavailable';
                    }
                }
                return item;
            }));

            return { 
                statusCode: 200, 
                headers, 
                body: JSON.stringify({ success: true, order }) 
            };
        } 

        // 404 triggers the frontend "Syncing..." retry logic
        return { 
            statusCode: 404, 
            headers, 
            body: JSON.stringify({ success: false, message: "Order not found in vault yet." }) 
        };
    } catch (error) {
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ success: false, message: error.message }) 
        };
    }
}

// 1. FETCH ALL MEMBERS WITH NEURAL ORDER HISTORY
case 'get-users': {
    try {
        const users = await db.collection('users').aggregate([
            {
                $lookup: {
                    from: 'orders', 
                    localField: 'email', 
                    foreignField: 'email', 
                    as: 'orders'
                }
            },
            {
                $project: {
                    password: 0, // Security: Remove passwords
                    // We keep 'orders' intact, only hiding sensitive Stripe/Payment IDs
                    "orders.paymentIntentId": 0,
                    "orders.stripeCustomerId": 0 
                }
            },
            { $sort: { createdAt: -1 } }
        ]).toArray();

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, users }) 
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: "VAULT_LINK_ERROR" }) };
    }
}
// 2. UPDATE USER PROFILE (NAME MODIFICATION)
case 'update-user': {
    const body = JSON.parse(event.body || "{}");
    const { userId, firstName, lastName } = body;

    if (!userId) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "MISSING_IDENTITY" }) };
    }

    try {
        await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { 
                $set: { 
                    firstName, 
                    lastName, 
                    updatedAt: new Date() 
                } 
            }
        );

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, message: "Identity Revised" }) 
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: "UPDATE_FAILED" }) };
    }
}

// 3. TOGGLE BAN STATUS
case 'moderate-user': {
    const body = JSON.parse(event.body || "{}");
    const { userId, action } = body;

    if (!userId) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "MISSING_IDENTITY" }) };
    }

    try {
        const isBanned = (action === 'ban');
        
        await db.collection('users').updateOne(
            { _id: new ObjectId(userId) },
            { $set: { isBanned: isBanned, updatedAt: new Date() } }
        );

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, message: `Identity ${action}ed` }) 
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: "MODERATION_FAILED" }) };
    }
}

// 4. PERMANENT DATA PURGE
case 'delete-user': {
    const body = JSON.parse(event.body || "{}");
    const { userId } = body;

    if (!userId) {
        return { statusCode: 400, headers, body: JSON.stringify({ message: "MISSING_IDENTITY" }) };
    }

    try {
        const result = await db.collection('users').deleteOne({ _id: new ObjectId(userId) });

        if (result.deletedCount === 0) {
            return { statusCode: 404, headers, body: JSON.stringify({ message: "USER_NOT_FOUND" }) };
        }

        return { 
            statusCode: 200, 
            headers, 
            body: JSON.stringify({ success: true, message: "Identity purged from vault" }) 
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ message: "PURGE_FAILED" }) };
    }
}
// --- 1. NEWSLETTER SUBSCRIPTION ---
case 'subscribe-newsletter': {
    try {
        const { email } = JSON.parse(event.body);
        if (!email || !email.includes('@')) {
            return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: "Invalid Email" }) };
        }

        const emailClean = email.toLowerCase().trim();

        const existing = await db.collection('newsletter').findOne({ email: emailClean });
        if (existing) {
            return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: "Already Subscribed" }) };
        }

        await db.collection('newsletter').insertOne({
            email: emailClean,
            subscribedAt: new Date(),
            status: 'active'
        });

        return { statusCode: 200, headers, body: JSON.stringify({ success: true, message: "Welcome to the Vault" }) };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}

// --- 2. GET BROADCAST AUDIENCE (Optimized for Unique Reach) ---
case 'get-broadcast-audience': {
    try {
        const [registered, guests, subscribers] = await Promise.all([
            db.collection('users').distinct('email'),
            db.collection('orders').distinct('email'),
            db.collection('newsletter').distinct('email')
        ]);

        // Use a Set to get the true unique reach across all collections
        const uniqueEmails = new Set([...registered, ...guests, ...subscribers]);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({
                success: true,
                total: uniqueEmails.size,
                registered: registered.length,
                guests: guests.length,
                newsletter: subscribers.length
            })
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}

// --- 3. GET ALL PRODUCTS (Keep for other Admin tools if needed) ---
case 'get-all-products': {
    try {
        const collections = ['wears', 'shorts', 'caps', 'jerseys', 'tanktops', 'tracksuits'];
        const allResults = await Promise.all(
            collections.map(col => 
                db.collection(col).find({}, { projection: { name: 1, price: 1, mainImage: 1 } }).toArray()
            )
        );
        
        const products = allResults.flat();
        const signedProducts = await Promise.all(products.map(async (p) => {
            const url = p.mainImage ? await getSecureUrl(p.mainImage) : null;
            return { ...p, mainImage: url };
        }));

        return { statusCode: 200, headers, body: JSON.stringify({ success: true, products: signedProducts }) };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}
case 'mass-broadcast': {
    try {
        const { template, subject, message, imageAssets } = JSON.parse(event.body);

        // A. Aggregate Audience
        const [registered, guests, subscribers] = await Promise.all([
            db.collection('users').distinct('email'),
            db.collection('orders').distinct('email'),
            db.collection('newsletter').distinct('email')
        ]);
        
        const targetList = [...new Set([...registered, ...guests, ...subscribers])]
            .filter(e => e && e.includes('@') && e.trim() !== "");

        if (targetList.length === 0) {
            return { statusCode: 400, headers, body: JSON.stringify({ success: false, message: "No recipients found." }) };
        }

        // --- B. AUTO-DESIGN ENGINE ---
        const themes = [
            { bg: "#000000", accent: "#ffffff", btn: "#ffffff", text: "#000000" }, // Midnight
            { bg: "#1a1a1a", accent: "#f3f3f3", btn: "#e67e22", text: "#ffffff" }, // Industrial
            { bg: "#ffffff", accent: "#000000", btn: "#000000", text: "#ffffff" }  // Minimalist
        ];
        const activeTheme = themes[new Date().getDate() % themes.length];

        // --- C. ASSET SIGNING & GRID FORMATTING ---
        let assetsHtml = "";
        if (template === 'arrivals' && imageAssets?.length > 0) {
            // Sign the private URLs once before the loop to save compute/latency
            // We use a 7-day expiry (604800s) because broadcast emails linger in inboxes
            const signedAssets = await Promise.all(imageAssets.map(async (img) => {
                try {
                    return await getSecureUrl(img, 604800); 
                } catch (err) {
                    console.error("ASSET_SIGNING_ERROR:", err);
                    return 'https://via.placeholder.com/400x500?text=Image+Unavailable';
                }
            }));

            const imageItems = signedAssets.map(url => `
                <div style="display: inline-block; width: 45%; margin: 2%; vertical-align: top;">
                    <div style="background: #ffffff; padding: 5px; border: 1px solid #eeeeee;">
                        <img src="${url}" style="width: 100%; height: auto; display: block; border-radius: 4px;">
                    </div>
                </div>`).join('');
            assetsHtml = `<div style="padding: 20px 0; text-align: center;">${imageItems}</div>`;
        }
        const formattedMessage = message.replace(/\n/g, '<br>');

        // --- D. MASTER RESPONSIVE TEMPLATE ---
        // Includes the Brand Logo + Brand Name "OUTFLICKZ"
        const emailHtml = `
            <!DOCTYPE html>
            <html>
                <head>
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                </head>
                <body style="margin: 0; padding: 0; background-color: #f6f6f6; font-family: 'Helvetica Neue', Arial, sans-serif;">
                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                        <tr>
                            <td align="center" style="padding: 20px 0;">
                                <table width="600" style="background: #ffffff; border-radius: 8px; overflow: hidden; max-width: 95%; border-bottom: 8px solid #000;">
                                    <tr>
                                        <td align="center" style="background: ${activeTheme.bg}; padding: 40px 20px;">
                                            <img src="https://i.imgur.com/kbSNFTc.png" alt="OUTFLICKZ" 
                                                 style="width: 100px; height: auto; display: block; filter: brightness(0) invert(1);">
                                            <h1 style="margin: 15px 0 0 0; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 24px; font-weight: 900; letter-spacing: 8px; color: ${activeTheme.bg === '#ffffff' ? '#000000' : '#ffffff'}; text-transform: uppercase;">
                                                OUTFLICKZ
                                            </h1>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td style="padding: 40px 30px; background: #ffffff;">
                                            <h2 style="text-transform: uppercase; font-size: 22px; letter-spacing: 2px; color: #111; margin-bottom: 20px;">${subject}</h2>
                                            <p style="line-height: 1.8; color: #444; font-size: 15px;">${formattedMessage}</p>
                                            ${assetsHtml}
                                            <div style="margin-top: 30px; text-align: center;">
                                                <a href="https://outflickz.com" 
                                                   style="background: #000000; color: #ffffff; padding: 15px 35px; text-decoration: none; 
                                                          font-weight: bold; border-radius: 4px; display: inline-block; font-size: 13px; letter-spacing: 2px;">
                                                    SHOP THE COLLECTION
                                                </a>
                                            </div>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td align="center" style="padding: 30px; background: #fafafa; border-top: 1px solid #eeeeee;">
                                            <p style="font-size: 11px; color: #999; margin: 0; letter-spacing: 1px;">&copy; ${new Date().getFullYear()} OUTFLICKZ. SECURED VAULT TRANSACTION.</p>
                                            <p style="font-size: 10px; color: #bbb; margin-top: 10px;">You are receiving this because you joined the OUTFLICKZ community.</p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
            </html>`;

        // E. Execution: Individual Dispatch Loop
        let dispatchedCount = 0;
        let failedEmails = [];

        for (const email of targetList) {
            try {
                await transporter.sendMail({
                    from: `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_USER}>`,
                    to: email,
                    subject: subject,
                    html: emailHtml
                });
                dispatchedCount++;
                // Anti-spam delay
                await new Promise(r => setTimeout(r, 200)); 
            } catch (err) {
                failedEmails.push({ email, error: err.message });
            }
        }

        // F. Performance Logging
        const broadcastLog = {
            timestamp: new Date(),
            subject: subject,
            totalAttempted: targetList.length,
            successfullySent: dispatchedCount,
            failedCount: failedEmails.length,
            imageAssetsUsed: imageAssets || []
        };
        await db.collection('broadcast_logs').insertOne(broadcastLog);

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ 
                success: true, 
                message: `Broadcast complete. Reached ${dispatchedCount} members.`,
                logId: broadcastLog._id 
            })
        };

    } catch (err) {
        console.error("BROADCAST_FATAL:", err);
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}

case 'get-broadcast-history': {
    try {
        const { masterKey } = JSON.parse(event.body || "{}");
        
        // Security Protocol: Match against Environment Variable
        if (!masterKey || masterKey !== process.env.MASTER_ACCESS_KEY) {
            console.error("Auth Failed: Provided key does not match environment variable.");
            return { 
                statusCode: 401, 
                headers, 
                body: JSON.stringify({ success: false, message: "Unauthorized Access" }) 
            };
        }

        const logs = await db.collection('broadcast_logs')
            .find({})
            .sort({ timestamp: -1 }) 
            .limit(50)
            .toArray();

        return {
            statusCode: 200,
            headers,
            body: JSON.stringify({ success: true, logs: logs })
        };
    } catch (err) {
        return { statusCode: 500, headers, body: JSON.stringify({ success: false, message: err.message }) };
    }
}

            default:
                return { statusCode: 404, headers, body: JSON.stringify({ message: "Action Not Recognized" }) };
        }
    } catch (err) {
        console.error("Critical Error:", err);
        return { 
            statusCode: 500, 
            headers, 
            body: JSON.stringify({ error: err.message }) 
        };
    }
};