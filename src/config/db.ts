import mongoose from 'mongoose'

export async function connectToDb(){

        try {
                await  mongoose.connect(process.env.MONGO_URI!)

                console.log(`Mongo connection done 🤷‍♀️`)
        } catch (error) {
                console.log(`MongoDB connection error: ${error}`)
                process.exit(1)
        }
}