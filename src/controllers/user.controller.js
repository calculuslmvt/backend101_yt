import { asyncHandler } from "../utils/asyncHandler.js";
import { APIError } from "../utils/apiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { APIResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken";

const generatAccessAndRefreshToken = async (userId) => {
    try {

        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false })
        return { accessToken, refreshToken };

    } catch (error) {
        console.log(error); 
        throw new APIError(500, "Error while creating refresh and access Token");
    }
}


const registerUser = asyncHandler(async (req, res) => {
     // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const {fullname, email, username, password} = req.body;
    // validation 
    if(
        [fullname, email, username, password]
        .some((value) => value?.trim() === "")
    ) {
        throw new APIError(400, "All fields are required"); 
    }

    // Already exits
    const existedUser = await User.findOne({
        $or: [{username}, {email}]
    });

    if(existedUser) {
        throw new APIError(409, "User with email or username already exists"); 
    };

    const avatarLocalPath = await req.files?.avatar[0]?.path;
    const coverImageLocalPath = await req.files?.coverImage?.[0]?.path;

    if(!avatarLocalPath) {
        throw new APIError(400, "Avatar file is required");
    };

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if(!avatar) {
        throw new APIError(400, "Avatar file not uploaded");
    }

    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase(), 
    });

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    );

    return res.status(201).json(
        new APIResponse(200, createdUser, "User registerd Successfully")
    );

});
const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie
    
    const {email, username, password} = await req.body;
    console.log(req.body);

    if(!username && !email) {
        throw new APIError(400, "username or email is required");
    };

    const user = await User.findOne({
        $or: [{username}, {email}]
    });

    if(!user){
        throw new APIError(404, "user does not exists");
    }
    
    const isPasswordValid = await user?.isPasswordCorrect(password);

    console.log(isPasswordValid); 

    if(!isPasswordValid) {
        throw new APIError(401, "Invalid user Password"); 
    };

    const { accessToken, refreshToken } = await generatAccessAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly: true,
        secure: true
    }


    console.log(refreshToken); 

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new APIResponse(
                200, 
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "user loggedIn successfully",
            )
        );

});

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1 // removing field from document 
            }
        },
        {
            new: true 
        }
    );

    const options = {
        httpOnly: true,
        secure: true
    };

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new APIResponse(200, {}, "User logged Out"))
});

const refreshAccessToken = asyncHandler(async (req, res) => {

    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if(!incomingRefreshToken) {
        throw new APIError(401, "unauthorized request");
    };

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken._id);

        if(!user) throw new APIError(401, "Invalid refresh Token");

        if(incomingRefreshToken !== user?.refreshToken) {
            throw new APIError(401, "Refresh Token expired or used"); 
        }

        const {accessToken, newRefreshToken} = generatAccessAndRefreshToken(user._id);

        const options = {
            httpOnly: true,
            secure: true
        }


        return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", newRefreshToken, options)
        .json(
            new APIResponse(
                200,
                {accessToken, newRefreshToken},
                "Access token Refreshed"
            )
        )

    } catch (error) {
        throw new APIError(401, error?.message || "Error while refreshing access token"); 
    }
})


export {registerUser, loginUser, logoutUser, refreshAccessToken};


