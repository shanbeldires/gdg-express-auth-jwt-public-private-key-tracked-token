import User from "../models/user.model.js";
import RefreshToken from "../models/refresh_token.model.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import {
  ACCESS_TOKEN_EXPIRE_DATE,
  ACCESS_TOKEN_PRIVATE_KEY,
  ACCESS_TOKEN_PUBLIC_KEY,
  REFRESH_TOKEN_EXPIRE_DATE,
  REFRESH_TOKEN_PRIVATE_KEY,
  REFRESH_TOKEN_PUBLIC_KEY,
} from "../config/env.js";

export const signUp = async (req, res, next) => {
  try {
    const { full_name, email, password } = req.body;

    if (!full_name || !email || !password) {
      const error = new Error("full_name, email, password are required");
      error.statusCode = 400;
      throw error;
    }

    const isEmailExist = await User.findOne({ email });
    if (isEmailExist) {
      const error = new Error("User already exists");
      error.statusCode = 409;
      throw error;
    }

    if (password.length < 8) {
      const error = new Error("Password must be at least 8 characters");
      error.statusCode = 409;
      throw error;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create(
      {
        full_name, email,
        password: hashedPassword
       }
      );

    const access_token = jwt.sign(
      { user_id: newUser._id },
      ACCESS_TOKEN_PRIVATE_KEY,
      { 
        algorithm: "HS256", 
        expiresIn: ACCESS_TOKEN_EXPIRE_DATE 
      }
    );

    const refresh_token = jwt.sign(
      { user_id: newUser._id },
      REFRESH_TOKEN_PRIVATE_KEY,
      { 
        algorithm: "HS256", 
        expiresIn: REFRESH_TOKEN_EXPIRE_DATE
      }
    );

    res.cookie("access_token", access_token, 
      { maxAge: 60000 * 15, 
        httpOnly: true, 
        sameSite: "lax", 
        secure: false 
      }
    );
    res.cookie("refresh_token", refresh_token, 
      { maxAge: 60000 * 60 * 24 * 7, 
        httpOnly: true, 
        sameSite: "lax", 
        secure: false 
      }
    );

    const hashed_refresh_token = crypto.createHash("sha256").update(refresh_token).digest("hex");
    let expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + 90);

    await RefreshToken.create(
      { 
        user_id: newUser._id,
        refresh_token: hashed_refresh_token, 
        expires_at 
      }
    );

    const userObj = newUser.toObject();
    delete userObj.password;

    res.status(201).json(
      { 
        success: true, 
        data: {
            user: userObj,
            access_token, 
            refresh_token 
          }
      }
    );

  } catch (err) {
    next(err);
  }
};

export const signIn = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      const error = new Error("email and password are required");
      error.statusCode = 400;
      throw error;
    }

    const user = await User.findOne({ email });
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    if (user.lockUntil && user.lockUntil > new Date()) {
      const error = new Error("Account locked. Try again later.");
      error.statusCode = 403;
      throw error;
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      user.wrongAttempts = (user.wrongAttempts || 0) + 1;
      if (user.wrongAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 10 * 60 * 1000);
      }
      await user.save();
      const error = new Error("Invalid credentials");
      error.statusCode = 401;
      throw error;
    }

    user.wrongAttempts = 0;
    user.lockUntil = null;
    await user.save();

    const access_token = jwt.sign(
      { user_id: user._id }, 
      ACCESS_TOKEN_PRIVATE_KEY, 
      {
         algorithm: "HS256", 
         expiresIn: ACCESS_TOKEN_EXPIRE_DATE
      }
    );
    const refresh_token = jwt.sign(
      { user_id: user._id }, 
      REFRESH_TOKEN_PRIVATE_KEY, 
      {  
         algorithm: "HS256",
         expiresIn: REFRESH_TOKEN_EXPIRE_DATE 
      }
    );

    res.cookie("access_token", access_token, 
      { 
        maxAge: 60000 * 15, 
        httpOnly: true, 
        sameSite: "lax", 
        secure: false

       }
      );

    res.cookie("refresh_token", refresh_token, 
      {
         maxAge: 60000 * 60 * 24 * 7, 
         httpOnly: true, 
         sameSite: "lax", 
         secure: false 
      }
    );

    const hashed_refresh_token = crypto.createHash("sha256").update(refresh_token).digest("hex");
    let expires_at = new Date();
    expires_at.setDate(expires_at.getDate() + 90);

    await RefreshToken.create(
      { 
        user_id: user._id, 
        refresh_token: hashed_refresh_token, 
        expires_at 
      }
    );

    const userObj = user.toObject();
    delete userObj.password;

    res.status(200).json(
      {
        success: true, 
        data: 
          { user: userObj, 
            access_token, 
            refresh_token 
          } 
     }
   );

  } catch (err) {
    next(err);
  }
};

export const refreshToken = async (req, res, next) => {
  try {
    const refresh_token = req.cookies?.refresh_token;
    if (!refresh_token) {
      const error = new Error("Refresh token missing");
      error.statusCode = 401;
      throw error;
    }

    const hashed_refresh_token = crypto.createHash("sha256").update(refresh_token).digest("hex");
    const db_token = await RefreshToken.findOne({ refresh_token: hashed_refresh_token });
    if (!db_token) {
      const error = new Error("Unauthorized");
      error.statusCode = 401;
      throw error;
    }

    const decoded = jwt.verify(refresh_token, REFRESH_TOKEN_PUBLIC_KEY);
    const access_token = jwt.sign(
        { user_id: decoded.user_id },
        ACCESS_TOKEN_PRIVATE_KEY, 
        { algorithm: "HS256",
          expiresIn: ACCESS_TOKEN_EXPIRE_DATE
        }
    );

    res.cookie("access_token", access_token,
       {  maxAge: 60000 * 15, 
          httpOnly: true, 
          sameSite: "lax",
          secure: false 
       }
    );

    res.status(201).json(
      { 
        success: true, 
        data: 
        { access_token } 
      }
    );

  } catch (err) {
    next(err);
  }
};

export const getUser = async (req, res, next) => {
  try {
    const id = req.user?._id;
    if (!id) {
      const error = new Error("Unauthorized");
      error.statusCode = 401;
      throw error;
    }

    const user = await User.findById(id).select("-password");
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    res.status(200).json(
      { 
        success: true, 
        data: user 
      }
    );

  } catch (err) {
    next(err);
  }
};

export const logout = async (req, res, next) => {
  try {
    const refresh_token = req.cookies?.refresh_token;
    if (refresh_token) {
      const hashed_refresh_token = crypto.createHash("sha256").update(refresh_token).digest("hex");                                                    
      await RefreshToken.findOneAndDelete({ refresh_token: hashed_refresh_token });
    }

    res.clearCookie("access_token", 
      {  
          httpOnly: true,
          sameSite: "lax",
          secure: false 
      }
    );

    res.clearCookie("refresh_token", 
      { 
         httpOnly: true,
         sameSite: "lax", 
         secure: false 
      }
    );

    res.status(200).json(
      { 
        success: true, 
        message: "Logged out successfully"
     }
    );

  } catch (err) {
    next(err);
  }
};