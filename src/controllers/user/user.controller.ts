import { Request, Response } from "express";


export async function getMeHandler(req:Request,res:Response){

        try {
                const authReq = req as any

                const  authUser = authReq.user

                return res.status(200).json({user:authUser})


        } catch (error) {
                return res.status(500).json({message:'Something went wrong'})
        }
}