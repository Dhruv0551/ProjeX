import dotenv from 'dotenv';
import app from './app.js';
import connectDB from './db/sql.js';

dotenv.config({
  path: './.env',
});
const port = process.env.PORT;

connectDB()
  .then(() => {
    app.listen(8080, () => {
      console.log(`Server listening to port: ${port}`);
    });
  })
  .catch((err) => {
    console.log('mongoDB connection Error', err);
    process.exit(1);
  });
