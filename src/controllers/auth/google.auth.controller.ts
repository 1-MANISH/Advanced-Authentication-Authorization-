import { Request, Response } from 'express'
import {OAuth2Client} from 'google-auth-library'
import { User } from '../../models/user.model'
import crypto from "crypto"
import { hashPassword } from '../../lib/hash'
import { createAccessToken, createRefreshToken } from '../../lib/token'
import { id } from 'zod/v4/locales'

export async function getGoogleClient(){
        const clientId  = process.env.GOOGLE_CLIENT_ID
        const clientSecret = process.env.GOOGLE_CLIENT_SECRET
        const redirectUri = process.env.GOOGLE_REDIRECT_URI


        if(!clientId || !clientSecret || !redirectUri){
                throw new Error(`Google client credential (id+secret is missing) is not set`)
        }

        return new OAuth2Client({
                clientId,
                clientSecret,
                redirectUri
        })
}

// one start authentication function and one start callback

// after we click on google login button - this function calls google auth start
export async function googleAuthStartHandler(_req:Request,res:Response){
        try {

                const client = await getGoogleClient()

                // create scope  - what information on success

                const url = client.generateAuthUrl({
                        access_type:"offline",
                        prompt:"consent",
                        scope:["openid","email","profile"]
                })

                //  directly we can redirect to google login page
                // postman - url as json 
                // return res.status(200).json({url})
                return res.redirect(url)

      

        } catch (error) {
                console.log(`Error while starting google auth: ${error}`)
                return res.status(500).json({message:'Internal server error , Something went wrong'})
        }
}

export async function googleAuthCallbackHandler(req:Request,res:Response){
        try {
                const code = req.query.code as string | undefined

                if(!code){
                        return res.status(400).json({message:'Code is missing'})
                }

                const client = await getGoogleClient()

                const {tokens}  = await client.getToken(code)

                // console.log(tokens,code)

                if(!tokens?.id_token){
                        return res.status(400).json({message:'Google ID token is missing'})
                }

                // verify id token and read user info from that
                const ticket = await client.verifyIdToken({
                        idToken:tokens.id_token,
                        audience:process.env.GOOGLE_CLIENT_ID
                })

                // console.log(ticket)

                const payload = ticket.getPayload()

                if(!payload?.email){
                        return res.status(400).json({message:'User email is missing'})
                }

                const email = payload?.email
                const emailVerified = payload?.email_verified

                if(!email || !emailVerified){
                        return res.status(400).json({message:'User email is not verified or missing'})
                }

                const normalizedEmail = email.toLowerCase().trim()

                let user = await User.findOne({email:normalizedEmail})

                if(!user){
                        // create new user

                        const randomPassword = crypto.randomBytes(16).toString('hex')

                        const passwordHash = await hashPassword(randomPassword)

                        user = await User.create({
                                email:normalizedEmail,
                                passwordHash,
                                name:payload?.name,
                                role:"user",
                                isEmailVerified:true,// google already done
                                twoFactorEnabled:false
                        })

                        // const accessToken = createAccessToken(
                        //         user._id.toString(),
                        //         user.role as "user" | "admin",
                        //         user.tokenVersion
                        // )

                        // const refreshToken = createRefreshToken(
                        //         user._id.toString(),
                        //         user.tokenVersion
                        // )

                        // const isProd = process.env.NODE_ENV ==="production"

                        // res.cookie(
                        //         'refreshToken',
                        //         refreshToken,
                        //         {
                        //                 httpOnly:true,
                        //                 secure:isProd,
                        //                 maxAge:7*24*60*60*1000,
                        //                 sameSite:'lax'
                        // })

                        // return res.status(200).json({
                        //         accessToken,
                        //         message:'Google login successfully',
                        //         user:{
                        //                 name:user.name,
                        //                 email:user.email,
                        //                 id:user._id,
                        //                 role:user.role
                        //         }
                        // })

                }else{
                        if(!user.isEmailVerified){

                                user.isEmailVerified=true
                                await user.save()

                        }

                        
                }
                const accessToken = createAccessToken(
                                user._id.toString(),
                                user.role as "user" | "admin",
                                user.tokenVersion
                        )

                        const refreshToken = createRefreshToken(
                                user._id.toString(),
                                user.tokenVersion
                        )

                        const isProd = process.env.NODE_ENV ==="production"

                        res.cookie(
                                'refreshToken',
                                refreshToken,
                                {
                                        httpOnly:true,
                                        secure:isProd,
                                        maxAge:7*24*60*60*1000,
                                        sameSite:'lax'
                        })

                        return res.status(200).json({
                                accessToken,
                                message:'Google login successfully',
                                user:{
                                        name:user.name,
                                        email:user.email,
                                        id:user._id,
                                        role:user.role
                                }
                        })

        } catch (error) {
                console.log(`Error while callback google auth: ${error}`)
                return res.status(500).json({message:'Internal server error , Something went wrong'})
        }
}