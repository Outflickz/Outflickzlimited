const nodemailer = require('nodemailer');

// 1. Configure the transporter for SMTP/Gmail
// NOTE: This uses environment variables (process.env) for credentials.
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS 
    },
    // Optional: Recommended security options for port 465 (SSL/TLS)
    secure: true, 
    port: 465, 
});

/**
 * Sends a generic email using the configured transporter.
 * @param {string} to - Recipient email address.
 * @param {string} subject - Email subject line.
 * @param {string} htmlContent - HTML content of the email body.
 */
async function sendMail(to, subject, htmlContent) {
    const mailOptions = {
        // Use the defined EMAIL_USER for the 'from' address
        from: `Outflickz Limited <${process.env.EMAIL_USER}>`, 
        to: to,
        subject: subject,
        html: htmlContent,
    };

    try {
        // 🛠️ FIX: The actual command to send the email is now awaited
        const info = await transporter.sendMail(mailOptions);
        console.log('✅ Email sent: %s', info.messageId);
        return true;
    } catch (error) {
        // Log the critical error detail for debugging
        console.error('❌ CRITICAL Error sending email:', error); 
        return false; 
    }
}

module.exports = { sendMail };