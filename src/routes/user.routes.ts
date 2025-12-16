import { Router } from "express"
import { getMeHandler } from "../controllers/user/user.controller"
import requireAuth from "../middleware/requireAuth"

const router = Router()

router.get('/me',requireAuth,getMeHandler)


export default router