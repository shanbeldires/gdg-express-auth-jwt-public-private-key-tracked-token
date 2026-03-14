import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
      full_name: {
        type: String,
        required: [true, "Full name is required"],
        minLength:[3,"Invalid Full Name"]
      },
      email: {
        type: String,
        required: [true, "Email is required"],
        lowercase: true,
        unique: true,
        trim: true,
        match: [/\S+@\S+\.\S+/, "Invalid email"],
      },
      password: {
        type: String,
        required: [true, "Password is required"],
        minLength:[8,"Password is not strong"]
      },
      wrongAttempts:{
        type:Number,
        default:0
      },
      lockUntil:{
        type:Date,
        default:null
      }
  },
  {
    timestamps:true
  }
);


const User = mongoose.model("User",userSchema)
export default User