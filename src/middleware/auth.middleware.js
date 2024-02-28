import {asyncHandler} from '../utils/asyncHandler.js';
import {APIError} from "../utils/apiError.js"
import jwt from 'jsonwebtoken';
import {User} from "../models/user.model.js"

const verifyJWT = asyncHandler(async (req, res, next)=> {

    try{
        const token = req.cookies?.accessToken || req
        .header("Autharization")?.replace("Bearer ", "");

        if(!token){
            throw new APIError(401, "Unathorized request");
        }

        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decodedToken?._id)
                                .select(" -password -refreshToken")

        if(!user) {
            throw new APIError(401, "Invalid Acces Token");
        }

        req.user = user;
        next(); 
                
    } catch(error) {
        throw new APIError(401, error?.message || "Invalid access Token");
    }

});

export {verifyJWT};

