import { body } from 'express-validator';

const registerValidator = () => {
  return [
    body('email')
      .trim()
      .notEmpty()
      .withMessage('Email is required')
      .isEmail()
      .withMessage('Email is Invalid'),

    body('username')
      .trim()
      .notEmpty()
      .withMessage('Username is Required')
      .isLowercase()
      .withMessage('Username must in lowercase')
      .isLength({ min: 4, max: 12 })
      .withMessage('Username must be between 4-12 characters'),

    body('password')
      .trim()
      .notEmpty()
      .withMessage('Password is Required')
      .isLength({ min: 8, max: 16 })
      .withMessage('Password length must be between 8-16 characters'),

    body('fullname').optional().trim(),
  ];
};

const userLoginValidator = () => {
  return [
    body('email').optional().isEmail().withMessage('Email is Invalid'),
    body('password').notEmpty().withMessage('Password cannot be Empty'),
  ];
};

const passwordChangeValidator = () => {
  return [
    body('oldPassword').notEmpty().withMessage('Old Password is Required'),
    body('newPassword').notEmpty().withMessage('New Password is Required'),
  ];
};

const forgotPasswordValidator = () => {
  return [
    body('email')
      .notEmpty()
      .withMessage('Email is Required')
      .isEmail()
      .withMessage('Email is Invalid'),
  ];
};

const resetForgotPasswordValidator = () => {
  return [body('newPassword').notEmpty().withMessage('Password is Required')];
};
export {
  registerValidator,
  userLoginValidator,
  passwordChangeValidator,
  forgotPasswordValidator,
  resetForgotPasswordValidator,
};
