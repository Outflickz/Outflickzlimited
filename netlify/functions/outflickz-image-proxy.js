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
        let finalKey = decodeURIComponent(key).trim().split('?')[0];

        // If it's a full URL, extract the path after the domain
        if (finalKey.includes('.com/')) {
            finalKey = finalKey.split('.com/').pop();
        }

        // Remove bucket name if it's at the start (e.g., "outflickz/vault/img.jpg")
        const bucketPrefix = bucketName + '/';
        if (finalKey.startsWith(bucketPrefix)) {
            finalKey = finalKey.substring(bucketPrefix.length);
        }

        // Clean leading slashes so we get "vault/image.jpg"
        finalKey = finalKey.replace(/^\/+/, '');

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