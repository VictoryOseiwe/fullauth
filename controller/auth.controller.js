import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { User } from "../model/user.model.js";
import {
  sendPasswordResetEmail,
  sendVerificationEmail,
} from "../utils/email.js";

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Token generators
const generateAccessToken = (user) => {
  return jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "15m" });
};

const generateRefreshToken = (user) => {
  return jwt.sign({ id: user.id }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
};

// Register a new user
export const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    if (password.length < 6)
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });

    const existingUser = await User.findOne({ where: { email } });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    const newUser = await User.create({
      username,
      email,
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires,
    });

    await sendVerificationEmail(
      email,
      verificationToken,
      verificationTokenExpires
    );

    res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      user: { username: newUser.username, email: newUser.email },
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Could not register user" });
  }
};

// Log in user
export const logIn = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and Password are required" });

    const existingUser = await User.findOne({ where: { email } });
    if (!existingUser)
      return res.status(404).json({ message: "User does not exist" });

    const isValidPassword = await bcrypt.compare(
      password,
      existingUser.password
    );
    if (!isValidPassword)
      return res.status(401).json({ message: "Invalid password" });

    if (!existingUser.isVerified)
      return res
        .status(403)
        .json({ message: "Please verify your email first" });

    const accessToken = generateAccessToken(existingUser);
    const refreshToken = generateRefreshToken(existingUser);

    // Update refresh tokens safely
    const updatedRefreshTokens = [
      ...(existingUser.refreshTokens || []),
      refreshToken,
    ];
    await existingUser.update({ refreshTokens: updatedRefreshTokens });

    // Optionally, send refresh token as HTTP-only cookie
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Login successful",
      accessToken,
      refreshToken,
      user: {
        id: existingUser.id,
        username: existingUser.username,
        email: existingUser.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Could not log in" });
  }
};

// Log out user from one browser
export const logOutFromCurrentBrowser = async (req, res) => {
  try {
    const { user } = req; // user injected by middleware (from access token)
    const refreshToken = req.cookies?.refreshToken; // token from cookie

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Find user in DB
    const isUser = await User.findByPk(user.id);
    if (!isUser) {
      return res.status(404).json({ message: "User not found" });
    }

    // Remove this specific refresh token (not all, unless desired)
    if (refreshToken) {
      const updatedTokens = (isUser.refreshTokens || []).filter(
        (token) => token !== refreshToken
      );
      await isUser.update({ refreshTokens: updatedTokens });
    } else {
      // If no cookie, fallback to clearing all refresh tokens
      await isUser.update({ refreshTokens: [] });
    }

    // Clear cookie from browser
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Could not log out" });
  }
};

// Log out user from all browsers
export const logOutFromAllBrowsers = async (req, res) => {
  try {
    const { user } = req;

    if (!user) return res.status(400).json({ message: "Unauthorized" });

    const isUser = await User.findByPk(user.id);
    if (!isUser) return res.status(404).json({ message: "User not found" });

    // Clear all refresh tokens
    await isUser.update({ refreshTokens: [] });

    // Clear cookie from browser
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res
      .status(200)
      .json({ message: "Logged out from all devices successfully" });
  } catch (error) {
    console.error("Logout all devices error:", error);
    res.status(500).json({ message: "Could not log out from all devices" });
  }
};

// Get current user
export const getCurrentUser = async (req, res) => {
  res.json({ user: req.user });
};

// updateUserProfile
export const updateUserProfile = async (req, res) => {
  try {
    const { user } = req;
    const { username, email } = req.body;

    if (!user) return res.status(400).json({ message: "Unauthorized" });

    const isUser = await User.findByPk(user.id);
    if (!isUser) return res.status(404).json({ message: "User not found" });

    // Update fields if provided
    if (username) isUser.username = username.toLowerCase();
    if (email) isUser.email = email.toLowerCase();

    await isUser.save();

    res.status(200).json({
      message: "Profile updated successfully",
      user: {
        id: isUser.id,
        username: isUser.username,
        email: isUser.email,
      },
    });
  } catch (error) {
    console.error("Update profile error:", error);
    res.status(500).json({ message: "Could not update user profile" });
  }
};

// Verify email
export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.params;

    const user = await User.findOne({ where: { verificationToken: token } });
    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    if (user.verificationTokenExpires < new Date()) {
      return res.status(400).json({ message: "Token has expired" });
    }

    await user.update({
      isVerified: true,
      verificationToken: null,
      verificationTokenExpires: null,
    });

    res.status(200).json({ message: "Email verified successfully" });
  } catch (error) {
    console.error("Email verification error:", error);
    res.status(500).json({ message: "Could not verify email" });
  }
};

// change password
export const changePassword = async (req, res) => {
  try {
    const { user } = req;
    const { currentPassword, newPassword } = req.body;

    if (!user) return res.status(400).json({ message: "Unauthorized" });

    const isUser = await User.findByPk(user.id);
    if (!isUser) return res.status(404).json({ message: "User not found" });

    const isValidPassword = await bcrypt.compare(
      currentPassword,
      isUser.password
    );
    if (!isValidPassword)
      return res.status(401).json({ message: "Current password is incorrect" });

    if (newPassword.length < 6)
      return res
        .status(400)
        .json({ message: "New password must be at least 6 characters" });

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    isUser.password = hashedNewPassword;
    await isUser.save();

    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Change password error:", error);
    res.status(500).json({ message: "Could not change password" });
  }
};

// reset password
/* This function sends a password reset email 
with a frontend url to the user such that when user 
clicks the link, they are redirected to a page alongside 
the reset token to send a reset password request. */
export const resetPasswordRequest = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email)
      return res.status(400).json({ message: "Email address is required" });

    const userEmail = await User.findOne({
      where: { email: email.toLowerCase() },
    });

    const userId = userEmail ? userEmail.id : null;

    if (!userEmail)
      return res.status(400).json({ message: "Email address not found" });

    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpires = new Date(Date.now() + 3600000); // 1 hour

    await userEmail.update({
      passwordResetToken: resetToken,
      passwordResetExpires: resetTokenExpires,
    });

    await sendPasswordResetEmail(email, resetToken, resetTokenExpires, userId);

    res.status(200).json({ message: "Password reset email sent successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Could not send password reset email" });
  }
};

// Resetting users password
export const resetPassword = async (req, res) => {
  try {
    const { userId } = req.query;
    const { token } = req.query;
    const { newPassword } = req.body;

    console.log("UserId:", userId);
    console.log("Token:", token);

    const user = await User.findByPk(userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    let resetPasswordToken = await User.findOne({
      where: { passwordResetToken: token },
    });

    if (!resetPasswordToken)
      return res.status(400).json({ message: "Invalid or expired token" });

    if (resetPasswordToken.passwordResetExpires < new Date()) {
      return res.status(400).json({ message: "Token has expired" });
    }

    if (newPassword.length < 6)
      return res
        .status(400)
        .json({ message: "New password must be at least 6 characters" });

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedNewPassword;
    user.passwordResetToken = null;
    user.passwordResetExpires = null;

    await user.save();

    res.status(200).json({ message: "Password reset successfully" });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({ message: "Could not reset password" });
  }
};

//delete user
export const deleteUser = async (req, res) => {
  try {
    const { user } = req;
    if (!user) return res.status(404).json({ message: "No user" });

    const isUser = await User.findByPk(user.id);
    if (!isUser) return res.status(400).json({ message: "User not found" });

    await isUser.destroy();

    res.status(200).json({ message: "Account deleted successfully" });
  } catch (error) {
    console.error("Could not delete user account", error);
    res.status(500).json({ message: "Could not delete account try again." });
  }
};
