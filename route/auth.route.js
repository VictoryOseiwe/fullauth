import express from "express";
import {
  register,
  changePassword,
  getCurrentUser,
  logIn,
  logOutFromAllBrowsers,
  logOutFromCurrentBrowser,
  resetPasswordRequest,
  updateUserProfile,
  verifyEmail,
  deleteUser,
  resetPassword,
} from "../controller/auth.controller.js";

import { authenticateToken } from "../middleware/auth.middleware.js";

const router = express.Router();

// Registration route
router.post("/register", register);

// Login route
router.post("/login", logIn);

// Logout from current browser
router.post("/logout", authenticateToken, logOutFromCurrentBrowser);

// Logout from all browsers
router.post("/logout-all", authenticateToken, logOutFromAllBrowsers);

// Get current user
router.get("/me", authenticateToken, getCurrentUser);

// Update user profile
router.put("/update-profile", authenticateToken, updateUserProfile);

// Verify email
router.get("/verify-email/:token", verifyEmail);

// Change password
router.post("/change-password", authenticateToken, changePassword);

// Reset password
router.post("/request-password-reset", resetPasswordRequest);

// Delete User
router.delete("/delete-user", authenticateToken, deleteUser);

// Resetting users password
router.post("/reset-password", resetPassword);

export default router;
