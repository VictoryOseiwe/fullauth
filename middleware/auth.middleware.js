import jwt from "jsonwebtoken";
import { User } from "../model/user.model.js";

const JWT_SECRET = process.env.JWT_SECRET;

export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res
        .status(401)
        .json({ message: "Access Token Required", error: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET); // Throws if invalid

    const dbUser = await User.findByPk(decoded.id);
    if (!dbUser) {
      return res.status(404).json({ message: "User not found" });
    }

    if (!dbUser.isVerified) {
      return res.status(403).json({ message: "Email not verified" });
    }

    req.user = dbUser;
    next();
  } catch (error) {
    console.error("Authentication error:", error);

    // Handle specific JWT errors
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        message: "Token expired",
        error: "Please refresh your token",
      });
    }

    if (error.name === "JsonWebTokenError") {
      return res.status(403).json({
        message: "Invalid token",
        error: "Authentication failed",
      });
    }

    // General server error
    res.status(500).json({
      message: "Authentication failed",
      error: "Server error",
    });
  }
};
