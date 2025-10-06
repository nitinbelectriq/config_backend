import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: 'email-smtp.us-east-1.amazonaws.com', // replace with your SES region endpoint
  port: 465, // SSL
  secure: true, // true for 465, false for 587
  auth: {
    user: 'AKIAWOAVSL2SCLMFOUMF',
    pass: 'BA2sK4So/BTlszxdtuCZxNIz49atI1kCDKnRy5+nnQob'
  }
});

export async function sendEmail(to, subject, text) {
  try {
    await transporter.sendMail({
      from: 'nitin.gautam@belectriq.co', // must be verified in SES
      to,
      subject,
      text
    });
    console.log('✅ Email sent successfully via SES');
    return true;
  } catch (err) {
    console.error('❌ Email sending failed:', err);
    return false;
  }
}
