
const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const { sendSMS } = require("../utils/sendSms"); // Fixed import path
const PasswordValidator = require('password-validator');
const logActivity = require('../middleware/activityLogger');

// Password policy schema
const passwordSchema = new PasswordValidator();
passwordSchema
  .is().min(8)
  .is().max(32)
  .has().uppercase()
  .has().lowercase()
  .has().digits()
  .has().symbols()
  .has().not().spaces();

// Register user and send OTP to phone
exports.register = async (req, res) => {
  const { name, email, password, phone } = req.body;
  // Password policy enforcement
  const validation = passwordSchema.validate(password, { list: true });
  if (validation.length > 0) {
    return res.status(400).json({
      message: 'Password does not meet security requirements',
      failedRules: validation
    });
  }
  // TODO: Prevent password reuse and add expiry logic
  try {
    const userExists = await User.findOne({ $or: [{ email }, { phone }] });
    if (userExists) {
      return res.status(400).json({ message: "User with email or phone already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = otpGenerator.generate(6, {
      digits: true,
      upperCaseAlphabets: false,
      specialChars: false,
      lowerCaseAlphabets: false,
    });

    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min from now

    const newUser = await User.create({
      name,
      email,
      phone,
      password: hashedPassword,
      otp,
      otpExpires,
      isVerified: false,
    });

    await sendSMS(phone, `Your OTP for registration is: ${otp}`);


    res.status(200).json({ message: "OTP sent to your phone number" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// Verify OTP and activate account
exports.verifyOtp = async (req, res) => {
  const { phone, otp } = req.body;
  try {
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ message: "User not found" });
    if (user.isVerified) return res.status(400).json({ message: "User already verified" });

    if (user.otp !== otp || user.otpExpires < Date.now()) {
      return res.status(400).json({ message: "Invalid or expired OTP" });
    }

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.status(200).json({
      message: "Verification successful",
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

// Login user (only if verified)
exports.login = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    if (!user.isVerified) {
      return res.status(403).json({ message: "Please verify your phone number first" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    // Log login activity (non-blocking, error-safe)
    try {
      logActivity({
        userId: user._id,
        action: 'login',
        details: `User ${user.email} logged in`,
        ip: req.ip
      });
    } catch (e) {
      // Logging error is ignored
    }
    res.status(200).json({
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      token,
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};
// Resend OTP
exports.resendOtp = async (req, res) => {
  const { phone } = req.body;
  try {
    const user = await User.findOne({ phone });
    if (!user) return res.status(400).json({ message: "User not found" });

    if (user.isVerified) {
      return res.status(400).json({ message: "User is already verified" });
    }

    const otp = otpGenerator.generate(6, {
      digits: true,
      upperCaseAlphabets: false,
      specialChars: false,
      lowerCaseAlphabets: false,
    });

    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min from now

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    await sendSMS(phone, `Your new OTP for registration is: ${otp}`);

    res.status(200).json({ message: "New OTP sent to your phone number" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
};

exports.passwordStrength = (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ message: 'Password is required' });
  const validation = passwordSchema.validate(password, { list: true });
  const isStrong = validation.length === 0;
  res.json({ isStrong, failedRules: validation });
};

// Password reset endpoint (add logging)
exports.resetPassword = async (req, res) => {
  const { email, newPassword } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Log password reset
    try {
      await logActivity({
        userId: user._id,
        action: 'reset_password',
        details: `Password reset for ${user.email}`,
        ip: req.ip
      });
    } catch (e) { }

    res.status(200).json({ message: 'Password reset successful' });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};