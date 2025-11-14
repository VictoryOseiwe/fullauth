import nodemailer from "nodemailer";
import "dotenv/config";

// Create reusable transporter object using SMTP transport
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true for port 465, false for others like 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Send verification email
export async function sendVerificationEmail(to, token, expires) {
  const verificationLink = `${process.env.APP_URL}/api/auth/verify-email/${token}`;

  const mailOptions = {
    from: `"Simple Auth" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Verify Your Email Address",
    html: `
      <h2>Welcome to Simple Auth 🎉</h2>
      <p>Please verify your email by clicking the link below:</p>
      <a href="${verificationLink}" target="_blank" 
         style="display:inline-block; background:#007bff; color:white; 
                padding:10px 15px; border-radius:5px; text-decoration:none;">
         Verify Email
      </a>
      <p>This link expires in ${expires} hour.</p>
    `,
  };

  await transporter.sendMail(mailOptions);
  console.log(`📧 Verification email sent to ${to}`);
}

// send password reset email
export async function sendPasswordResetEmail(to, token, expires, userId) {
  const resetLink = `${process.env.APP_URL}/api/auth/reset-password?token=${token}&userId=${userId}`; // Frontend url

  const mailOptions = {
    from: `"Simple Auth Password Reset" <${process.env.EMAIL_USER}>`,
    to,
    subject: "Password Reset Request",
    html: `
      <h2>Password Reset Request</h2>
      <p>Click the link below to reset your password:</p>
      <a href="${resetLink}" target="_blank" 
         style="display:inline-block; background:#dc3545; color:white; 
                padding:10px 15px; border-radius:5px; text-decoration:none;">
         Reset Password
      </a>
      <p>This link expires in ${expires} hour.</p>
    `,
  };

  await transporter.sendMail(mailOptions);
  console.log(`📧 Password reset email sent to ${to}`);
}
