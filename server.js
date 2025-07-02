import express from 'express';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dbConnect from './config/dbConnect.js';
import authRouter from './Router/authrouter.js';
import userRouter from './Router/userRoute.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

dbConnect();
const allowedOrigin = ['https://2a8b7218.user-verify.pages.dev'];

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: allowedOrigin,
  credentials: true
}));

app.get('/', (req, res) => {
  res.send('Welcome to the server and API is working!');
});

app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
