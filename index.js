const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const morgan = require("morgan");

const fs = require("fs");
const path = require("path");

const ApiError = require("./utils/apiError");
const globalError = require("./middlewares/errMidlewer");
const dotenv = require("dotenv");

// Load environment variables from config.env file
dotenv.config({ path: "./config.env" });

const authRouter = require("./Routes/authRoutes");
const questionRoute = require("./Routes/questionRoute");

mongoose
  .connect(process.env.DB_URL)
  .then((con) => {
    console.log(`Mogoose Host :${con.connection.host}`);
  })
  .catch(() => console.log(`Server is not connected to MongoDB...`));

const app = express();

app.use("/uploads", express.static("uploads"));
app.use("/audios", express.static("uploads"));

app.use(cors());

app.use(express.json());

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/questions", questionRoute);

const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "access.log"),
  { flags: "a" }
);

app.use(morgan("combined", { stream: accessLogStream }));
accessLogStream.on("error", (err) => {
  console.error("Stream error:", err);
});

app.all("*", (req, res, next) => {
  // const err = new Error(`Can't find this route ; ${req.originalUrl}`);
  // next(err.message);
  next(new ApiError(`Can't find this route ; ${req.originalUrl}`, 400));
});

// Global Error (only dev mode)
app.use(globalError);

app.listen(3001, () => {
  console.log("server connected to port 3001");
});
