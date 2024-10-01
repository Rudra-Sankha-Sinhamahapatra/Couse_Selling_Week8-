import express, { Response } from "express"
import zod from "zod"
import jwt, { JwtPayload } from "jsonwebtoken"
import bcrypt from "bcrypt"
import { userModel as User,purchaseModel as Purchase,courseModel as Course } from "../db/db"
import { JWT_USER_PASSWORD } from "../config/config"
import { userMiddleware } from "../middlewares/user"
import { signInBody, signUpBody } from "../zod"

export const UserRouter = express.Router();


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

UserRouter.post("/signin",async(req:any,res:any)=>{
const {success} = signInBody.safeParse(req.body);

if(!success) {
    return res.status(403).json({
        message:"You are not logged in"
    })
}

try {
   const existingUser = await User.findOne({
    email:req.body.email
   });

   if(!existingUser) {
    return res.status(401).json({
     message:"User doesnt exists,please create an account"
    })
   }

   if(!existingUser.password){
    return res.status(404).json({
        message:"No password in db"
    })
   }
   const validPassword = await bcrypt.compare(req.body.password, existingUser.password);

   if(!validPassword){
    return res.status(411).json({
        message:"Invalid Password"
    })
   }

    const token = jwt.sign({id:existingUser._id},JWT_USER_PASSWORD as string);
    
    return res.status(200).json({
        message:"Login Succeed",
        existingUser,
        token
    })
}
catch(e:any){
    return res.status(500).json({
        message:"Internal Server Error"
    })
}
})