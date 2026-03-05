const AWS = require('aws-sdk');

const s3 = new AWS.S3({
    accessKeyId: process.env.IDRIVE_ACCESS_KEY,
    secretAccessKey: process.env.IDRIVE_SECRET_KEY,
    endpoint: new AWS.Endpoint(process.env.IDRIVE_ENDPOINT),
    region: process.env.IDRIVE_REGION,
    s3ForcePathStyle: true,
});

exports.handler = async (event) => {
    const key = event.queryStringParameters.key;
    if (!key) return { statusCode: 400, body: "Missing Key" };

    try {
        const data = await s3.getObject({
            Bucket: process.env.IDRIVE_BUCKET_NAME,
            Key: key
        }).promise();

        return {
            statusCode: 200,
            headers: {
                "Content-Type": data.ContentType,
                // Cache the image in the user's browser for 30 days
                "Cache-Control": "public, max-age=2592000, immutable",
            },
            body: data.Body.toString('base64'),
            isBase64Encoded: true,
        };
    } catch (err) {
        console.error("Proxy Error:", err);
        return { statusCode: 404, body: "Image Not Found" };
    }
};