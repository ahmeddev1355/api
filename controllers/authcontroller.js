const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const moment = require("moment");
const asyncHandler = require("express-async-handler");
// const nodemailer = require("nodemailer");
const ApiError = require("../utils/apiError");
const sendEmail = require("../utils/sendEmail");

const userModel = require("../models/userModel");
const generateToken = require("../utils/createToken");
const { sanitizeUser } = require("../utils/sanatizeData");
const Factory = require("../controllers/handlerFactory");

// @Desc      signUp
// @route     /api/v1/auth/signup
// @Access    Public
exports.register = asyncHandler(async (req, res, next) => {
  const deviceId = uuidv4();
  const { name, email, password } = req.body;

  const expiresAt = moment().add(1, "month").toDate();
  // 1 - Create the user in the database
  const user = await userModel.create({
    name,
    email,
    password,
    activeDevice: {
      deviceId,
      token: "",
      lastLogin: new Date(),
    },
    expiresAt,
  });

  // 2 - Generate the JSON web token (JWT)
  const token = generateToken(user._id);

  // 3 - Update the token in the user's activeDevice after generating it
  user.activeDevice.token = token;
  await user.save();

  // 4 - Send the user data and token back to the client
  res.status(201).json({
    data: sanitizeUser(user), // Return sanitized user data
    token, // Return the generated token
    deviceId: user.activeDevice.deviceId,
  });
});

// @Desc      login
// @route     /api/v1/auth/login
// @Access    Public
exports.login = asyncHandler(async (req, res, next) => {
  // 1) check if password and email in the body
  const { email, password } = req.body;

  const user = await userModel.findOne({ email });

  // 2) check user exiset & chech if password if correct
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return next(new ApiError("incorrect email or password", 401));
  }

  const deviceId = uuidv4();

  // log out from frst device
  if (user.activeDevice && user.activeDevice.deviceId !== deviceId) {
    user.activeDevice.token = null; // Invalidate the old token
  }

  const newToken = generateToken(user._id);

  user.activeDevice = {
    deviceId,
    token: newToken,
    lastLogin: new Date(),
  };

  await user.save();

  // console.log(newToken);
  // console.log(user);

  // 3) generate token
  // const token = generateToken(user._id);
  // 4) send response to client side
  res.status(200).json({ data: sanitizeUser(user), token: newToken, deviceId });
});

exports.protect = asyncHandler(async (req, res, next) => {
  // 1) check if token exist , true get it
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }
  if (!token) {
    return next(
      new ApiError(
        "You are not login, please login to get access to this route"
      ),
      401
    );
  }

  // 2) varify token (expired token , no change happend)
  const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);

  // 3) check if user exists
  const currentUser = await userModel.findById(decoded.userId);

  if (!currentUser) {
    return next(
      new ApiError(
        "The user that belong to this token does no longer exist",
        401
      )
    );
  }

  // 4) Check if the user's account has expired
  if (currentUser.role !== "admin") {
    if (currentUser.expiresAt && currentUser.expiresAt < new Date()) {
      return next(
        new ApiError("Your account has expired. Please contact support.", 403)
      );
    }
  }

  // 5) check if user change his password after token created
  if (currentUser.passwordChangedAt) {
    const passwordChangedTimeStamp = parseInt(
      currentUser.passwordChangedAt.getTime() / 1000,
      10
    );
    if (passwordChangedTimeStamp > decoded.iat) {
      return next(
        new ApiError(
          "User recentely change his password, Please login again..",
          401
        )
      );
    }
  }

  // 6) Check if the provided token matches the active device's token
  if (!currentUser.activeDevice || currentUser.activeDevice.token !== token) {
    return next(
      new ApiError(
        "Invalid token. You may have logged in from another device.",
        403
      )
    );
  }

  // 5) check if user is active
  // if (!currentUser.active) {
  //   return next(
  //     new ApiError("Your account is Deleted, please contact support", 401)
  //   );
  // }

  req.user = currentUser;

  next();
});

// @desc    Authorizition {User Permissions}
// ["admin", "manager"]
exports.allowedTo = (...roles) =>
  // 1) access rools
  asyncHandler(async (req, res, next) => {
    // 2) access registred user (req.user.role)
    if (!roles.includes(req.user.role)) {
      return next(
        new ApiError("You are not allowed to access this route", 403)
      );
    }
    next();
  });

// @Desc      Forgot Password
// @route     POST /api/v1/auth/forgotPassword
// @Access    Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  // 1) get user by email
  const user = await userModel.findOne({ email: req.body.email });
  if (!user) {
    return next(
      new ApiError(`there is no user with this email: ${req.body.email}`, 404)
    );
  }
  // 2) if user exist, Generate hash reset random 6 digits and save it in db
  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

  const hashedResetCode = crypto
    .createHash("sha256")
    .update(resetCode)
    .digest("hex");

  // save hashed password reset code into db
  user.passwordResetCode = hashedResetCode;

  // add expiration time
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000; // expires after 10 mins
  user.passwordResetVerified = false;

  await user.save();
  // 3) send the reset code via email
  const message = `Hi ${user.name} 
                    We received a request to reset the password on your E-Shop account.
                    ${resetCode}
                    Enter this code to complete the reset.
                    The E-Shop Team`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Your password reset code (valid for 10 minutes)",
      message,
    });
  } catch (error) {
    // Reset password reset related fields for the user
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = undefined;

    await user.save();

    return next(new ApiError("there is an error in sending email", 500));
  }
  res.status(200).json({ status: "success", msg: "Reset code sent to email" });
});

// @Desc      Verify Password Reset Code
// @route     POST /api/v1/auth/verifyResetCode
// @Access    Public
exports.verifyPassResetCode = asyncHandler(async (req, res, next) => {
  //1- get user by reset code
  const hashedResetCode = crypto
    .createHash("sha256")
    .update(req.body.resetCode)
    .digest("hex");

  const user = await userModel.findOne({
    passwordResetCode: hashedResetCode,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ApiError(`Reset code invalid or expired`, 404));
  }

  // 2- reset code valid
  user.passwordResetVerified = true;

  // save user (passwordResetCode && passwordResetExpires)
  await user.save();

  res.status(200).json({
    status: "success",
  });
});

// @Desc      Reset Password
// @route     POST /api/v1/auth/resetPassword
// @Access    Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const user = await userModel.findOne({ email: req.body.email });

  if (!user) {
    return next(new ApiError("There is no user with this email", 404));
  }

  // check if reset code verified
  if (!user.passwordResetVerified) {
    return next(new ApiError("Reset code not verified", 400));
  }

  user.password = req.body.newPassword;

  user.passwordResetCode = undefined;
  user.passwordResetExpires = undefined;
  user.passwordResetVerified = undefined;

  await user.save();

  // 3- generate token
  const token = generateToken(user._id);
  res.status(200).json({ token });
});

exports.getLoggedUserData = asyncHandler(async (req, res, next) => {
  req.params.id = req.user._id;
  next();
});

exports.getUser = Factory.getOne(userModel);
