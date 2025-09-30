import nodemailer from 'nodemailer';

// Direct credentials (no .env)
const transporter = nodemailer.createTransport({
  host: 'smtp.belectriq.co',   // your mail server
  port: 587,                   // usually 587 for TLS
  secure: false,               // true if using port 465
  auth: {
    user: 'nitin.gautam@belectriq.co', // your email
    pass: 'Belectriq@1234#'            // your password
  }
});

export async function sendEmail(to, subject, text) {
  const from = 'nitin.gautam@belectriq.co';
  const msg = { from, to, subject, text };
  
  try {
    await transporter.sendMail(msg);
    console.log('✅ Email sent successfully');
    return true;
  } catch (err) {
    console.error('❌ Email sending failed:', err);
    return false;
  }
}
