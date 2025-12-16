import { Router } from "express";
import { googleAuthCallbackHandler, googleAuthStartHandler } from "../controllers/auth/google.auth.controller";

const router = Router()

router.get('/startAuth',googleAuthStartHandler)

router.get('/callback',googleAuthCallbackHandler)


export default router