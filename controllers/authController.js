import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import dotenv from 'dotenv';
dotenv.config();

export const register = async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: "User already exists with this email" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    const user = await newUser.save();
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: 'Registration Successful',
      text: `Hello ${user.name},\n\nThank you for registering an account with us.\n\nBest regards,\nYour Service Team`,
    };
    await transporter.sendMail(mailOptions);
    return res.status(201).json({ success: true, message: "User registered successfully" });
  } catch (error) {
    console.error("Registration error:", error.message);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: "Invalid email or password" });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "Invalid email or password" });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,
      subject: 'Login Successful',
      text: `Hello ${user.name},\n\nYou have successfully logged in to your account.\n\nBest regards,\nYour Service Team`,
    };
    await transporter.sendMail(mailOptions);
    return res.status(200).json({ success: true, message: "Login successful" });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const logout = (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
  });
  return res.status(200).json({ success: true, message: "Logged out successfully" });
};

export const sendOtp = async (req, res) => {
  const userId = req.userId;
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.isAccountVerified) return res.status(400).json({ success: false, message: "Account already verified" });
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.verifyOtp = otp;
    user.verifyOtpExpiresAt = Date.now() + 24 * 60 * 60 * 1000;
    await user.save();
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: 'Verification OTP',
      text: `Your OTP is ${otp}. It is valid for 24 hours.`,
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Send OTP error:", err.message);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

export const verifyEmail = async (req, res) => {
  const { otp } = req.body;
  const userId = req.userId;
  if (!userId || !otp) {
    return res.status(400).json({ success: false, message: "Missing user ID or OTP" });
  }
  try {
    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    if (user.isAccountVerified) return res.status(400).json({ success: false, message: "Account already verified" });
    const storedOtp = String(user.verifyOtp).trim();
    const inputOtp = String(otp).trim();
    if (!user.verifyOtpExpiresAt || user.verifyOtpExpiresAt < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }
    if (storedOtp !== inputOtp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpiresAt = null;
    await user.save();
    return res.status(200).json({
      success: true,
      message: "Email verified successfully",
      user: {
        id: user._id,
        email: user.email,
        isAccountVerified: user.isAccountVerified,
      },
    });
  } catch (error) {
    console.error("Email verification error:", error);
    return res.status(500).json({ success: false, message: "Server error during email verification" });
  }
};

export const resetOpt = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetOtp = otp;
    user.resetOtpExpires = Date.now() + 5 * 60 * 1000;
    await user.save();
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: 'Password Reset OTP',
      text: `Hello ${user.name},\n\nYour password reset OTP is: ${otp}\nThis OTP is valid for 5 minutes.\n\nRegards,\nYour Service Team`,
    };
    await transporter.sendMail(mailOptions);
    return res.status(200).json({ success: true, message: "OTP sent successfully" });
  } catch (err) {
    console.error("Reset OTP error:", err.message);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const resetPassword = async (req, res) => {
  const { email, newPassword, otp } = req.body;
  if (!email || !newPassword || !otp) {
    return res.status(400).json({ success: false, message: 'Email, OTP, and new password are required' });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }
    const storedOtp = String(user.resetOtp).trim();
    const inputOtp = String(otp).trim();
    if (!storedOtp || storedOtp !== inputOtp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }
    if (user.resetOtpExpires < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP has expired" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    user.resetOtp = "";
    user.resetOtpExpires = null;
    await user.save();
    return res.status(200).json({ success: true, message: "Password changed successfully" });
  } catch (err) {
    console.error("Reset password error:", err.message);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
};

export const userDetail = async (req, res) => {
  try {
    const userId = req.userId;
    if (!userId) {
      return res.status(400).json({ success: false, message: 'userId is required' });
    }
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    res.status(200).json({
      success: true,
      userData: {
        name: user.name,
        isAccountVerified: user.isAccountVerified,
      },
    });
  } catch (error) {
    console.error('Error in userDetail:', error.message);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
};
