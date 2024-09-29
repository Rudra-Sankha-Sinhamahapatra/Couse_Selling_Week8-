import express, { Response } from "express"
import zod from "zod"
import jwt, { JwtPayload } from "jsonwebtoken"
import bcrypt from "bcrypt"
import { userModel as User,purchaseModel as Purchase,courseModel as Course } from "../db/db"
import { JWT_USER_PASSWORD } from "../config/config"
import { userMiddleware } from "../middlewares/user"

export const UserRouter = express.Router();

const signUpBody = zod.object({
    email:zod.string().email(),
    password:zod.string(),
    firstName:zod.string(),
    lastName:zod.string()
})

UserRouter.post("/signup",async(req:any,res:any)=>{
const {success} = signUpBody.safeParse(req.body);

if(!success) {
    return res.status(411).json({
        message: "Email Already exists or incorrect inputs"
    })
}
try {
    const existingUser = await User.findOne({
        email:req.body.email
    });

    if(existingUser) {
        return res.status(401).json({
            message:"Email already used or incorrect inputs"
        })
    }

    const hashedPassword = await bcrypt.hash(req.body.password,10);

    const user = await User.create({
        email:req.body.email,
        password:hashedPassword,
        firstName:req.body.firstName,
        lastName:req.body.lastName
    })

    const userId = user._id;

    const token = jwt.sign({
        id:userId
    },JWT_USER_PASSWORD as string);

    return res.json({
        message:"Sign Up Succeed",
        user,
        token
    })

}
catch(e:any){
    return res.status(500).json({
        message:"Internal Server Error"
    })
}
})
