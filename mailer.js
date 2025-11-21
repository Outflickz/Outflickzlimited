// mailer.js

const nodemailer = require('nodemailer');

// 1. Configure the transporter for SMTP/Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail', // Use 'gmail' for simplicity
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    // Optional: Recommended security options
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
        from: `Outflickz Limited <${process.env.EMAIL_USER}>`,
        to: to,
        subject: subject,
        html: htmlContent,
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent: %s', info.messageId);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        // In production, you might log this error but still return true 
        // to the user for sensitive requests like 'forgot-password'.
        return false; 
    }
}

module.exports = { sendMail };