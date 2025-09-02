import express from 'express';
import cors from 'cors';

const app = express();

// --------------------config--------------------
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true, limit: '16kb' }));
app.use(express.static('public'));
app.use(cookieParser());

// -------------------cors config----------------
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(',') || 'https://localhost:5173',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type'],
  }),
);

// ------------------Routes---------------------
import healthCheckRoute from './routes/healthcheck.route.js';
import authRouter from './routes/auth.route.js';
import cookieParser from 'cookie-parser';

app.use('/api/v1/healthcheck', healthCheckRoute);
app.use('/api/v1/auth', authRouter);

app.get('/', (req, res) => {
  res.send('Home Route');
});

export default app;
