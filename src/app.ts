// express application logic+ cookies+cors

import express from 'express'
import cookieParser from "cookie-parser"


// routes import
import authRouter from "./routes/auth.routes"
import userRouter from "./routes/user.routes"
import adminRouter from "./routes/admin.routes"

// express application
const app = express()


// for json request - middleware
app.use(express.json())
// to pass req.cookie
app.use(cookieParser()) 



app.get('/health',(req,res)=>{
        res.json({status:'ok'})
})

app.use('/auth',authRouter)
app.use('/user',userRouter)
app.use('/admin',adminRouter)

export default app