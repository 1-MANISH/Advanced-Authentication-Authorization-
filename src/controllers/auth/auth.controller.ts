
import {Request, Response} from 'express'
import { forgetPasswordSchema, loginSchema, registerSchema } from './auth.schema'
import { User } from '../../models/user.model'
import { checkPassword, hashPassword } from '../../lib/hash'
import jwt from "jsonwebtoken"
import { sendEmail } from '../../lib/email'
import { createAccessToken, createRefreshToken, verifyRefreshToken } from '../../lib/token'
import crypto from "crypto"
import {authenticator} from "otplib"


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
                        <p><a href="${url}">${url}</a></p>

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

                const {email,password,twoFactorCode}  = result.data

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

                // 2 factor auth
                if(user.twoFactorEnabled){

                        if(!twoFactorCode || typeof twoFactorCode !== 'string'){
                                return res.status(400).json({
                                        message:"Two factor code is missing"
                                })
                        }

                        if(!user.twoFactorSecret){
                                return res.status(400).json({
                                        message:"Two factor is mis configured for this account"
                                })
                        }

                        // verify the two factor code using otp lib

                        const isValid = authenticator.check(twoFactorCode,user.twoFactorSecret)

                        if(!isValid){
                                return res.status(400).json({
                                        message:"Invalid two factor code"
                                })
                        }
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

export async function refreshHandler(req:Request,res:Response){

        try {
                const token = req.cookies?.refreshToken as string | undefined

                if(!token){
                        return res.status(401).json({
                                message:'Refresh token is missing'
                        })
                }

                const payload =  verifyRefreshToken(token)

                const user = await User.findById(payload.sub)

                if(!user){
                        return res.status(401).json({message:'User not found'})
                }

                if(user.tokenVersion !== payload.tokenVersion){
                         return res.status(401).json({message:'Refresh token invalidated'})
                }

                const newAccessToken =  createAccessToken(user._id.toString(),user.role,user.tokenVersion)

                const newRefreshToken = createRefreshToken(user._id.toString(),user.tokenVersion)

                const isProd = process.env.NODE_ENV ==="production"

                res.cookie('refreshToken',
                        newRefreshToken,
                        {
                                httpOnly:true,
                                secure:isProd,
                                sameSite:"lax",
                                maxAge:7*24*60*60*1000
                        }
                )

                return res.status(200).json({
                        message:"Token refreshed",
                        accessToken:newAccessToken,
                        user:{
                                id:user._id,
                                email:user.email,
                                role:user.role,
                                isEmailVerified:user.isEmailVerified,
                                twoFactorEnabled:user.twoFactorEnabled
                        }
                })

        } catch (error) {
                console.log(`Error while refresh handler : ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}

export async function logoutHandler(_req:Request,res:Response){

        res.clearCookie('refreshToken',{
                path:'/'
        })

        return res.status(200).json({
                message:`Logout successfully`
        })
}

export async function forgotPasswordHandler(req:Request,res:Response){

        try {
                const result = forgetPasswordSchema.safeParse(req.body)
                if(!result.success){
                        return  res.status(400).json({
                                message:"Invalid data! ",
                                errors:result.error.flatten()
                        })
                }
                const {email}  = result.data
                const normalizedEmail = email.toLowerCase().trim()

                const user = await User.findOne({email:normalizedEmail})

                if(!user){
                        return res.json({
                                message:`If an account with this email exists, we will send a reset link`
                        })
                }

                const rawToken = crypto.randomBytes(32).toString('hex')

                const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex')

                // console.log(tokenHash)

                user.resetPasswordToken=tokenHash
                user.resetPasswordExpires=new Date(Date.now() + 15*60*1000) // 15 minutes

                await user.save()

                const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`

                await sendEmail(
                        user.email,
                        `Reset password link`,
                        `
                        <p>Your requested for resetting password click on below link :</p>
                        <p> <a href=${resetUrl}>${resetUrl}</a> </p>
                        
                        <p>Thanks </p>
                        `
                )

                return res.status(200).json({
                        message:`Reset password link has been sent on registered email , it will expires in 15 minutes from now`
                })


        } catch (error) {
                 console.log(`Error forget password handler : ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}

export async function resetPasswordHandler(req:Request,res:Response){

        try {
               const {token,password} = req.body as {token?:string;password?:string} 

               if(!token){
                        return res.status(400).json({message:`Reset token is missing`})
               }
               if(!password || password.length < 6){
                        return res.status(400).json({message:`Password must be at least 6 characters long`})
               }

               const tokenHash = crypto.createHash('sha256').update(token).digest('hex')

               const user = await User.findOne({resetPasswordToken:tokenHash,
                        resetPasswordExpires:{$gt:new Date()}
               })

               if(!user){
                        return res.status(400).json({message:`Invalid reset token or token expired`})
               }

               user.passwordHash = await hashPassword(password)
               user.resetPasswordToken=undefined
               user.resetPasswordExpires=undefined
               user.tokenVersion = user.tokenVersion+1

               await user.save()

               return res.status(200).json({
                message:`Password reset successfully`
               })
        

        } catch (error) {
                 console.log(`Error resetting  password handler : ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}

// set two factor
export async function twoFASetupHandler(req:Request,res:Response){


        try {
                const authReq = req as any
                const authUser = authReq.user

                if(!authUser){
                        return res.status(401).json({message:'Not authenticated user'})
                }
                
                const user = await User.findById(authUser.id)

                if(!user){
                        return res.status(401).json({message:'User not found'})
                }

                // if(user.twoFactorEnabled){
                //         return res.status(400).json({message:'Two factor already enabled'})
                // }

                // generate secret
                const secret = authenticator.generateSecret()
                const issuer = 'NodeAdvancedAuthAPP'
                const optAuthUrl = authenticator.keyuri(user.email,issuer,secret)// generate otp auth url - qrcode

                user.twoFactorSecret = secret
                user.twoFactorEnabled = false // we need to verify it using code

                await user.save()

                return res.status(200).json({
                        message:'Two factor setup successfully',
                        optAuthUrl,// we need to create QR code
                        secret
                })


        } catch (error) {
                 console.log(`Error setting two  factor handler : ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}


export async function twoFAVerifyHandler(req:Request,res:Response){

        try {
                const authReq = req as any
                const authUser = authReq.user

                if(!authUser){
                        return res.status(401).json({message:'Not authenticated user'})
                }
                
                const {code} = req.body as {code?:string}

                if(!code){
                        return res.status(400).json({message:'2 Factor Code is missing'})
                }

                const user = await User.findById(authUser.id)

                if(!user){
                        return res.status(401).json({message:'User not found'})
                }

                if(!user.twoFactorSecret){
                        return res.status(400).json({message:'Two factor not enabled, for you yet'})
                }

                const isValid = authenticator.check(code,user.twoFactorSecret)

                if(!isValid){
                        return res.status(400).json({message:'Invalid 2 Factor Code'})
                }

                user.twoFactorEnabled = true

                await user.save()

                return res.status(200).json({
                        message:'Two factor verified successfully , Setup done for 2FA',
                        twoFactorEnabled:true
                })

        } catch (error) {
                console.log(`Error verify two  factor handler : ${error}`)
                return res.status(500).json({
                        message:"Internal Server error Something went wrong",
                        error
                })
        }
}