
import {Request, Response} from 'express'
import { registerSchema } from './auth.schema'
import { User } from '../../models/user.model'
import { hashPassword } from '../../lib/hash'
import jwt from "jsonwebtoken"


function getAppUrl(){
        return `${process.env.APP_URL || `http://localhost:${process.env.PORT}`}`
}

export async function registerHandler(req:Request, res:Response){
        try {

                const result = registerSchema.safeParse(req.body)
                
                if(!result.success){
                        return  res.status(400).json({
                                message:"Invalid data! ",
                                errors:result.error.flatten()
                        })
                }

                const {name,email,password}  = result.data

                const normalizedEmail = email.toLowerCase().trim()

                const existingUser = await User.findOne({email:normalizedEmail})

                if(existingUser){
                        return res.status(409).json({
                                message:"Email is already in use! Please try with different email"
                        })
                }

                const passwordHash = await hashPassword(password)

                const newlyCreatedUser = await User.create({
                        name,
                        email:normalizedEmail,
                        passwordHash,
                        role:'user',
                        isEmailVerified:false,
                        twoFactorEnabled:false
                })

                // email verification part - mail sent to user for verification

                const verifyToken = jwt.sign(
                        {
                        sub:newlyCreatedUser._id
                        },
                        process.env.JWT_ACCESS_SECRET!,
                        {
                                expiresIn:"1d"
                        }
                )

                const url = `${getAppUrl}/auth/verify-email?token=${verifyToken}`
                
        } catch (error) {
                
        }
}