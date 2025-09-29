import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

export async function sendEmail(to, subject, text) {
  const from = process.env.EMAIL_FROM || 'no-reply@example.com';
  const msg = { from, to, subject, text };
  // In production, consider adding text/html and proper templates.
  return transporter.sendMail(msg);
}
