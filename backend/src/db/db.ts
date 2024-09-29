import mongoose from "mongoose";

const Schema = mongoose.Schema;
const objectId = mongoose.Types.ObjectId;

const userSchema = new Schema ({
    email: {type:String,unique:true},
    password:String,
    firstName:String,
    lastName: String
})


const adminSchema = new Schema ({
    email: {type:String,unique:true},
    password:String,
    firstName:String,
    lastName: String
})

const courseSchema = new Schema({
    title:String,
    description:String,
    price:String,
    imageUrl:String,
    creatorId:objectId
});

const purchaseSchema = new Schema({
    userId:objectId,
    courseId:objectId
})

export const userModel = mongoose.model("user",userSchema);
export const adminModel = mongoose.model("admin",adminSchema);
export const courseModel = mongoose.model("course",courseSchema);
export const purchaseModel = mongoose.model("purchase",purchaseSchema);