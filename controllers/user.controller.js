import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { ACCESS_TOKEN_PUBLIC_KEY } from "../config/env.js";

export const getUser = async (req, res, next) => {
  try {
    const access_token = req.cookies?.access_token;
    if (!access_token) {
      const error = new Error("Access token missing");
      error.statusCode = 401;
      throw error;
    }

    const decoded = jwt.verify(access_token, ACCESS_TOKEN_PUBLIC_KEY, { algorithms: ["RS256"] });
    const id = decoded.user_id;

    const user = await User.findById(id).select("-password");
    if (!user) {
      const error = new Error("User not found");
      error.statusCode = 404;
      throw error;
    }

    res.status(200).json({ success: true, data: user });

  } catch (err) {
    next(err);
  }
};