import nodemailer from 'nodemailer';

// Configure transporter
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // TLS for port 587
  auth: {
    user: 'noreply@belectriq.co', // Gmail/Workspace email
    pass: 'vvshlnbtgdbpijal'      // Gmail App Password
  }
});

// Generic send email function
export async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: '"BelectriQ" <noreply@belectriq.co>', // Sender address
      to,
      subject,
      html, // HTML content for emails
      text: html.replace(/<[^>]+>/g, '') // plain-text fallback
    });
    console.log('✅ Email sent successfully');
    return true;
  } catch (err) {
    console.error('❌ Email sending failed:', err);
    return false;
  }
}
  