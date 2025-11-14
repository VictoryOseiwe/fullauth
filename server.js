import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import helment from "helmet";
dotenv.config();
import { db } from "./config/db.js";
import { User } from "./model/user.model.js";
import authRoutes from "./route/auth.route.js";

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helment());
app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Test route
app.get("/", (req, res) => {
  res.send("Server is running");
});

// Auth routes
app.use("/api/auth", authRoutes);

// synch db
await db
  .sync()
  .then(() => {
    console.log("Database synchronized");
  })
  .catch((err) => {
    console.error("Error synchronizing database:", err);
  });

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
