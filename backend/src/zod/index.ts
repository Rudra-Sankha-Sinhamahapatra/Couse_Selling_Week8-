import zod from "zod"

export const signUpBody = zod.object({
    email:zod.string().email(),
    password:zod.string(),
    firstName:zod.string(),
    lastName:zod.string()
})

export const signInBody = zod.object({
    email:zod.string().email(),
    password:zod.string(),
})