import mongoose from "mongoose"
import { DB_URI } from "../config/env.js"

const connectToDatabase = async () => {
    if (!DB_URI) {
        console.error("DB_URI is not defined. Check your .env file or environment variables.");
        return;
    }

    try {
        await mongoose.connect(DB_URI);
        console.log("Database connected successfully");
    } catch (err) {
        console.error("Failed to connect to database:", err.message || err);
        process.exit(1);
    }
};

export default connectToDatabase;