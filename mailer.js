const nodemailer = require('nodemailer');

// 1. Configure the transporter for SMTP/Gmail
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS 
    },
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
        // --- 🛠️ ACTUAL SENDING COMMAND IS NOW ACTIVE ---
        const info = await transporter.sendMail(mailOptions);
        
        // 🟢 SUCCESS LOG
        console.log('✅ Email sent successfully.');
        console.log(`- Recipient: ${to}`);
        console.log(`- Subject: ${subject}`);
        console.log(`- Message ID: ${info.messageId}`); 
        // ------------------------------------------------
        
        return true;
    } catch (error) {
        
        // 🔴 CRITICAL FAILURE LOG (This will show the specific cause like 'Invalid login' or 'Connection error')
        console.error('❌ CRITICAL ERROR: Failed to send email via Nodemailer.'); 
        console.error(`- Target: ${to} | Subject: ${subject}`);
        console.error('- Detailed Error:', error);
        // --------------------------------------------------------------------------------------------------
        
        return false; 
    }
}

module.exports = { sendMail };