
const express = require("express");
const router = express.Router();
const { register, login, verifyOtp, resendOtp, passwordStrength } = require("../controllers/authController");

router.post("/register", register);
router.post("/verify-otp", verifyOtp); // ✅ NEW: OTP verification
router.post("/resend-otp", resendOtp); // ✅ NEW: Resend OTP
router.post("/login", login);
router.post("/password-strength", passwordStrength);

module.exports = router;