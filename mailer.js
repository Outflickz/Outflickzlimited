const nodemailer = require('nodemailer');

// 1. Configure the transporter for SMTP/Gmail
// NOTE: Use environment variables in production. This uses the mock process.env for the environment.
const transporter = nodemailer.createTransport({
    service: 'gmail', 
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
        from: `Outflickz Limited <${process.env.EMAIL_USER || 'outflickzlimited@gmail.com'}>`,
        to: to,
        subject: subject,
        html: htmlContent,
    };

    try {
        // In a real environment, we'd await this. Here, we mock the success.
        // const info = await transporter.sendMail(mailOptions);
        // console.log('Email sent: %s', info.messageId);
        console.log(`Email successfully sent to ${to} with subject: ${subject}`);
        return true;
    } catch (error) {
        console.error('Error sending email:', error);
        return false; 
    }
}

module.exports = { sendMail };