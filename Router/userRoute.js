import express from 'express';
import {userDetail}  from '../controllers/authController.js';
import userAuth from '../middleware/authmiddle.js'

const userRouter =express.Router();

userRouter.get('/data',userAuth,userDetail);


export default userRouter;