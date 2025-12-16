// express application logic+ cookies+cors

import express from 'express'
import cookieParser from "cookie-parser"



// express application
const app = express()


// for json request - middleware
app.use(express.json())
// to pass req.cookie
app.use(cookieParser()) 



app.get('/health',(req,res)=>{
        res.json({status:'ok'})
})

export default app