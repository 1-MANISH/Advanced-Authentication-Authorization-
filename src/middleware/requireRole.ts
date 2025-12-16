import { Request,Response,NextFunction } from "express";


 function requireRole(role:'user' |'admin'){

        return (req:Request,res:Response,next:NextFunction)=>{

                const authReq = req as any

                const authUser = authReq.user

                if(!authUser){
                        return res.status(401).json({message:'You are not auth user !, your cant enter into buildings'})
                }

                if(authUser.role !== role){
                        return res.status(401).json({message:'You are not authorized to access this route !, your cant enter into this buildings'})
                }

                next()
        }
}

export default requireRole