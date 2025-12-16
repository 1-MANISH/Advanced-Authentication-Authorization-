import { Request, Response } from "express";
import { User } from "../../models/user.model";


export async function getUsersHandler(_req:Request,res:Response){

        try {
                const users = await User.find({},{
                        email:1,
                        role:1,
                        id:1,
                        isEmailVerified:1,
                        name:1,
                        createdAt:1
                }).sort({createdAt:-1}).lean()


                return res.status(200).json({
                        users
                })
        } catch (error) {
                return res.status(500).json({message:'Something went wrong'})
        }
}