import express from "express"
import { PORT } from "./config/env.js"
import connectToDatabase from "./database/mongodb.js"
import errorMiddleware from "./middlewares/error.middleware.js"
import authRouter from "./routes/auth.routes.js"
import userRouter from "./routes/user.routes.js"
import cookieParser from "cookie-parser"
const app = express()
app.use(express.json())
app.use(express.urlencoded({extended:false}))
app.use(cookieParser())
app.use((req, res, next) => {
  console.log("Incoming request:", req.method, req.url);
  next();
});

app.use("/api/v1/auth",authRouter)
app.use("/api/v1/users",userRouter)
app.use(errorMiddleware)
app.listen(process.env.PORT || PORT,()=>{
    connectToDatabase();
    console.log(`Server is listening on port ${PORT}`)
})