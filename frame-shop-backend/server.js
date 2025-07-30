
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db");
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// General rate limiter (all requests)
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(generalLimiter);

// Auth-specific rate limiter (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login/register attempts per windowMs
  message: { message: 'Too many attempts, please try again later.' }, // return as JSON
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/auth/', authLimiter);

// Test route
app.get("/", (req, res) => {
  res.send("🎯 Helmet Shop API is running...");
});

// Routes
app.use("/api/auth", require("./routes/authRoutes"));
app.use("/api/helmets", require("./routes/frameRoutes")); // Updated route name
app.use("/api/helmet-configs", require("./routes/frameConfigRoutes")); // Updated route name
app.use("/api/orders", require("./routes/orderRoutes"));
app.use("/api/upload", require("./routes/uploadRoutes"));
app.use("/api/payments", require("./routes/paymentRoutes"));
app.use("/api/activity-logs", require("./routes/activityLogRoutes"));

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error("❌ Global Error:", err.stack);
  res.status(500).json({ message: "Server error", error: err.message });
});

// Unhandled Promise Rejections
process.on("unhandledRejection", (err) => {
  console.error("UNHANDLED REJECTION 🔥", err.message);
  process.exit(1);
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Helmet Shop Server running at http://localhost:${PORT}`);
  console.log("🔧 Environment variables check:");
  console.log("- RESEND_API_KEY:", !!process.env.RESEND_API_KEY);
  console.log("- FROM_EMAIL:", process.env.FROM_EMAIL);
  console.log("- KHALTI_PUBLIC_KEY:", !!process.env.KHALTI_PUBLIC_KEY);
  console.log("- KHALTI_SECRET_KEY:", !!process.env.KHALTI_SECRET_KEY);
});

