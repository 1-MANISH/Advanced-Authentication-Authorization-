
import {Request, Response} from 'express'
import { loginSchema, registerSchema } from './auth.schema'
import { User } from '../../models/user.model'
import { checkPassword, hashPassword } from '../../lib/hash'
import jwt from "jsonwebtoken"
import { sendEmail } from '../../lib/email'
import { createAccessToken, createRefreshToken } from '../../lib/token'


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

                const url = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`

                await sendEmail(
                        newlyCreatedUser.email,
                        `Verify your email`,
                        `
                        <p>please verify your email by clicking on this link :</p>
                        <p><a href="${url}">link</a></p>

                        <p>Thanks 🙏</p>
                        `
                )

                return res.status(201).json({
                        message:'User registered , please verify your email',
                        user:{
                                id:newlyCreatedUser._id,
                                name:newlyCreatedUser.name,
                                email:newlyCreatedUser.email,
                                role:newlyCreatedUser.role,
                                isEmailVerified:newlyCreatedUser.isEmailVerified
                        }
                })
                
        } catch (error) {

                console.log(`Error while registering user: ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}

export async function verifyEmailHandler(req:Request,res:Response){

        const token = req.query.token as string | undefined

        

        if(!token){
                return res.status(400).json({
                        message:'Verification token is missing'
                })
        }

        try {
                const payload = jwt.verify(token,process.env.JWT_ACCESS_SECRET!)  as {
                        sub:string
                }

                const user = await User.findById(payload.sub)

                if(!user){
                        return res.status(400).json({
                                message:'User not found'
                        })
                }

                if(user.isEmailVerified){
                        return res.json({
                                message:'Email is already verified'
                        })
                }

                user.isEmailVerified=true
                await user.save()

                return res.json({
                        message:`Email is now  verified , you can login`
                })


        } catch (error) {
                console.log(`Error while verifying  user: ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }



}

export  async function loginHandler(req:Request,res:Response){

       try {
                const result = loginSchema.safeParse(req.body)
                
                if(!result.success){
                        return  res.status(400).json({
                                message:"Invalid data! ",
                                errors:result.error.flatten()
                        })
                }

                const {email,password}  = result.data

                const normalizedEmail = email.toLowerCase().trim()

                const user = await User.findOne({email:normalizedEmail})

                if(!user){
                        return res.status(400).json({
                                message:"Invalid Email or password! Please signup"
                        })
                }

                const ok = await checkPassword(password,user.passwordHash)

                if(!ok){
                        return res.status(400).json({
                                message:"Invalid Email or password! Please signup"
                        })
                }

                if(!user.isEmailVerified){
                        return res.status(400).json({
                                message:"Please verify your email , before login"
                        })
                }

                const accessToken = createAccessToken(user._id.toString(),user.role,user.tokenVersion)

                const refreshToken = createRefreshToken(user._id.toString(),user.tokenVersion)

                // save refresh token

                const isProd = process.env.NODE_ENV==="production"

                res.cookie(
                        'refreshToken',
                        refreshToken,{
                                httpOnly:true,
                                secure:isProd ,// abhi test me false otherwise true
                                sameSite:'lax',
                                maxAge:7*24*60*60*1000

                        }
                )

                return res.status(200).json({
                        message:'Login is successful',
                        accessToken,
                        user:{
                                id:user._id, 
                                email:user.email,
                                role:user.role,
                                isEmailVerified:user.isEmailVerified,
                                twoFactorEnabled:user.twoFactorEnabled
                        }
                })


       } catch (error) {
                console.log(`Error while login user: ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
       } 

}