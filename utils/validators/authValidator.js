const { check } = require("express-validator");
const validatorMiddleware = require("../../middlewares/validatorMiddleware");

const userModel = require("../../models/userModel");

exports.signupValidator = [
  // check("name")
  //   .notEmpty()
  //   .withMessage("User Required")
  //   .isLength({ min: 2 })
  //   .withMessage("Too short User name"),
  check("email")
    .notEmpty()
    .withMessage("Email Required")
    .isEmail()
    .withMessage("Invalid Email Address")
    .custom((val) =>
      userModel.findOne({ email: val }).then((user) => {
        if (user) {
          return Promise.reject(new Error("E-mail already used"));
        }
      })
    ),

  check("password")
    .notEmpty()
    .withMessage("Password Required")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
  validatorMiddleware,
];
exports.loginValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email Required")
    .isEmail()
    .withMessage("Invalid Email Address"),

  check("password")
    .notEmpty()
    .withMessage("Password Required")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters"),
  validatorMiddleware,
];
