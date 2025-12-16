// entry point
import dotenv from "dotenv"
import { connectToDb } from "./config/db";
import http from "http"
import app from "./app";
// config
dotenv.config()



async function startServer(){

        await connectToDb()

        const server = http.createServer(app)

        server.listen(process.env.PORT || 5000,()=>{
                console.log(`Server is now listening to port ${process.env.PORT}`)
        })

}

startServer().catch(err=>{
        console.log(`Error while starting the server`)
        process.exit(1)
})