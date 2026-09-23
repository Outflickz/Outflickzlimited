const AWS = require('aws-sdk');

const s3 = new AWS.S3({
    accessKeyId: process.env.IDRIVE_ACCESS_KEY,
    secretAccessKey: process.env.IDRIVE_SECRET_KEY,
    endpoint: new AWS.Endpoint(process.env.IDRIVE_ENDPOINT),
    region: process.env.IDRIVE_REGION, 
    s3ForcePathStyle: true,
    signatureVersion: 'v4'
});

exports.handler = async (event) => {
    const bucketName = process.env.IDRIVE_BUCKET_NAME || 'outflickz';
    const key = event.queryStringParameters ? event.queryStringParameters.key : null;

    if (!key) return { statusCode: 400, body: "Missing Key" };

    try {
        let rawKey = decodeURIComponent(key).trim();
        let finalKey = rawKey;

        // Safely extract pathname if a full URL is passed (works for any TLD/domain)
        try {
            const parsedUrl = new URL(rawKey);
            finalKey = parsedUrl.pathname;
        } catch (e) {
            // Not a full URL, treat as a direct relative key/path
            finalKey = rawKey.split('?')[0];
        }

        // Remove leading slashes
        finalKey = finalKey.replace(/^\/+/, '');

        // Remove bucket name if it's at the start (e.g., "outflickz/vault/img.jpg")
        const bucketPrefix = bucketName + '/';
        if (finalKey.startsWith(bucketPrefix)) {
            finalKey = finalKey.substring(bucketPrefix.length);
        }

        console.log(`DEBUG_IDRIVE: Bucket=${bucketName} | Key=${finalKey}`);

        const signedUrl = await s3.getSignedUrlPromise('getObject', {
            Bucket: bucketName,
            Key: finalKey,
            Expires: 3600 
        });

        return {
            statusCode: 302,
            headers: { "Location": signedUrl, "Access-Control-Allow-Origin": "*" },
            body: '' 
        };
    } catch (err) {
        console.error("PROXY_ERROR:", err.message);
        return { statusCode: 500, body: err.message };
    }
};