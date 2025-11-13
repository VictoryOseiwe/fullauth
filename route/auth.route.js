import express from "express";
import {
  register,
  changePassword,
  getCurrentUser,
  logIn,
  logOutFromAllBrowsers,
  logOutFromCurrentBrowser,
  resetPassword,
  updateUserProfile,
  verifyEmail,
} from "../controller/auth.controller.js";

const router = express.Router();

// Registration route
router.post("/register", register);

// Login route
router.post("/login", logIn);

// Logout from current browser
router.post("/logout", logOutFromCurrentBrowser);

// Logout from all browsers
router.post("/logout-all", logOutFromAllBrowsers);

// Get current user
router.get("/me", getCurrentUser);

// Update user profile
router.put("/update-profile", updateUserProfile);

// Verify email
router.get("/verify-email/:token", verifyEmail);

// Change password
router.post("/change-password", changePassword);

// Reset password
router.post("/reset-password", resetPassword);

export default router;
