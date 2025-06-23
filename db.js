const mongoose=require('mongoose');
require('dotenv').config();
const MONGO_URI = process.env.MONGO_URI;

const connectDB = async () => {
    try{
        const conn = await mongoose.connect(MONGO_URI, {
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000
        });
        console.log(`mongoDB connected: ${conn.connection.host}`);
    }catch(error) {
        console.log(`error in connecting with DB: ${error.message}`);
        process.exit(1);
    }
}

module.exports = connectDB;