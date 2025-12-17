import {Router} from 'express'
import { forgotPasswordHandler, loginHandler, logoutHandler, refreshHandler, registerHandler, resetPasswordHandler, twoFASetupHandler, twoFAVerifyHandler, verifyEmailHandler } from '../controllers/auth/auth.controller'
import requireAuth from '../middleware/requireAuth'


const router = Router()


router.post('/register',registerHandler)

router.post('/login',loginHandler)

router.get('/verify-email',verifyEmailHandler)

router.post('/refresh',refreshHandler)

router.post('/logout',logoutHandler)

router.post('/forget-password',forgotPasswordHandler)

router.post('/reset-password',resetPasswordHandler)

router.post('/2fa/setup',requireAuth,twoFASetupHandler)

router.post('/2fa/verify',requireAuth,twoFAVerifyHandler)

export default router

