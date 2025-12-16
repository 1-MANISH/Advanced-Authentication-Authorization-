import { Router } from "express";
import requireAuth from "../middleware/requireAuth";
import requireRole from "../middleware/requireRole";
import { getUsersHandler } from "../controllers/admin/admin.controller";

const router = Router()

// auth , admin
router.get('/users', requireAuth , requireRole('admin'), getUsersHandler)

export default router