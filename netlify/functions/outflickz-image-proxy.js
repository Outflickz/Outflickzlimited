const AWS = require('aws-sdk');

const s3 = new AWS.S3({
    accessKeyId: process.env.IDRIVE_ACCESS_KEY,
    secretAccessKey: process.env.IDRIVE_SECRET_KEY,
    endpoint: new AWS.Endpoint(process.env.IDRIVE_ENDPOINT),
    region: process.env.IDRIVE_REGION, 
    s3ForcePathStyle: true,
});

exports.handler = async (event) => {
    let key = event.queryStringParameters.key;
    if (!key) return { statusCode: 400, body: "Missing Key" };

    try {
        // 1. Decode the key in case it was double-encoded by the CDN wrap
        // This converts %252F back to /
        key = decodeURIComponent(key);

        // 2. If the key is a full URL, extract just the path
        if (key.includes('.com/')) {
            key = key.split('.com/')[1].split('?')[0];
        }

        // 3. Remove the bucket name if it's prepended to the path
        const bucketName = process.env.IDRIVE_BUCKET_NAME;
        if (key.startsWith(`${bucketName}/`)) {
            key = key.replace(`${bucketName}/`, '');
        }

        // 4. Clean leading/trailing slashes and whitespace
        key = key.replace(/^\/+|\/+$/g, '').trim();

        const data = await s3.getObject({
            Bucket: bucketName,
            Key: key
        }).promise();

        return {
            statusCode: 200,
            headers: {
                "Content-Type": data.ContentType || "image/webp",
                "Cache-Control": "public, max-age=2592000, immutable",
                // Help Netlify CDN understand this is an image
                "X-Content-Type-Options": "nosniff"
            },
            body: data.Body.toString('base64'),
            isBase64Encoded: true,
        };
    } catch (err) {
        // Log the exact key that failed so you can check it in iDrive
        console.error(`S3 Proxy Error | Bucket: ${process.env.IDRIVE_BUCKET_NAME} | Key: [${key}] | Error: ${err.message}`);
        
        return { 
            statusCode: 404, 
            body: JSON.stringify({ error: "Image Not Found", key: key }) 
        };
    }
};