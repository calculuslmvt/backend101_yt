import dotenv from "dotenv";
import connectDB from './db/index.js'
import { app } from './app.js'

dotenv.config({
    path: './.env'
});

connectDB()
.then(() => {
    app.listen(process.env.PORT || 8001, () => {
        console.log(`Server is running at PORT : ${process.env.PORT}`);
    });
    app.on("error", (error) => {
        console.log("ERR: ", error);
        throw error; 
    });
})
.catch((error) => {
    console.log("MONGO db connection failed !!!!", error);
});

