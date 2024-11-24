const nodemailer = require('nodemailer');

const send2FACodeByEmail = async (email, code) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',  // ou o serviço que está utilizando
            auth: {
                user: process.env.EMAIL_USER,  // seu e-mail completo
                pass: process.env.EMAIL_PASS,  // sua senha ou senha de aplicativo
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,  // e-mail do remetente
            to: email,  // e-mail do destinatário
            subject: 'Your 2FA Verification Code',
            text: `Your 2FA verification code is: ${code}`,
        };

        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Error sending email');
    }
};

module.exports = { send2FACodeByEmail };
