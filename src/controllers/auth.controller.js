import { User } from '../models/user.model.js';
import { ApiResponse } from '../utils/api-response.js';
import { asyncHandler } from '../utils/async-handler.js';
import { ApiError } from '../utils/api-error.js';
import {
  emailVerificationMailGen,
  forgotPasswordMailGen,
  sendEmail,
} from '../utils/mail.js';
import Mailgen from 'mailgen';
import jwt from 'jsonwebtoken';

const generateAccessAndRefreshToken = async (userID) => {
  try {
    const user = await User.findById(userID);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      'Something went Offside while generating access token.',
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  const { email, username, password, role } = req.body;

  const existingUser = await User.findOne({
    $or: [{ username }, { email }],
  });

  if (existingUser) {
    throw new ApiError(409, 'User with this name or email already exists');
  }

  const user = await User.create({
    email,
    password,
    username,
    isEmailVerified: false,
  });

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Please verify Your Email',
    MailgenContent: emailVerificationMailGen(
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  const createdUser = await User.findById(user._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationExpiry',
  );

  if (!createdUser)
    throw new ApiError(500, 'Something went wrong while registering User');

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { user: createdUser },
        'User registered Successfully, verification sent to your provided email',
      ),
    );
});

const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  if (!email) throw new ApiError(400, 'Email field is mandatory');

  const user = await User.findOne({ email });

  if (!user) throw new ApiError(400, 'Invalid email');

  const isPassValid = await user.isPasswordCorrect(password);

  if (!isPassValid) throw new ApiError(400, 'Invalid Password');

  const { accessToken, refreshToken } = await generateAccessAndRefreshToken(
    user._id,
  );
  const loggedUser = await User.findById(user._id).select(
    '-password -refreshToken -emailVerificationToken -emailVerificationExpiry',
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie('accessToken', accessToken, options)
    .cookie('refreshToken', refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedUser,
          accessToken,
          refreshToken,
        },
        'User Logged in Successfully',
      ),
    );
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: null,
      },
    },
    {
      new: true,
    },
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie('accessToken', options)
    .clearCookie('refreshToken', options)
    .json(new ApiResponse(200, 'User logged Out'));
});

const currentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, 'Current User fetched Successfully'));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params;

  if (!verificationToken)
    throw new ApiError(400, 'Email Verification is Missing');

  let hashedToken = crypto
    .createHash('sha256')
    .update(verificationToken)
    .digest('hex');

  user = await User.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpiry: { $gt: Date.now() },
  });

  if (!user) throw new ApiError(400, 'Token is Expired or Invalid');

  user.emailVerificationExpiry = undefined;
  user.emailVerificationToken = undefined;

  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });
  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { isEmailVerified: true },
        'Email has been verified',
      ),
    );
});

const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user?._id);

  if (!user) throw new ApiError(404, 'User Does not Exist!');

  if (user.isEmailVerified)
    throw new ApiError(409, 'Email is already verified');
  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: 'Please verify Your Email',
    MailgenContent: emailVerificationMailGen(
      `${req.protocol}://${req.get('host')}/api/v1/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(ApiResponse(200, {}, 'Mail has been sent to your EmailID'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
  const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
  if (!refreshToken) throw new ApiError(401, 'Unauthorized Access');

  try {
    const decodedToken = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    );

    const user = await User.findById(decodedToken?._id);
    if (!user) throw new ApiError(401, 'Inavlid Refresh Token');

    if (refreshToken != user?.refreshToken)
      throw new ApiError(401, 'Requested Token has Expired');

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save();

    return res
      .status(200)
      .cookie('accessToken', accessToken, options)
      .cookie('refreshToken', refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          'AccessToken Refreshed',
        ),
      );
  } catch (error) {
    throw new ApiError(401, 'Invalid RefreshToken');
  }
});

const forgotPasswordRequest = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) throw new ApiError(401, "User Doesn't Exist");

  const { unHashedToken, hashedToken, tokenExpiry } =
    user.generateTemporaryToken();
  user.forgotPasswordToken = hashedToken;
  user.forgotPasswordExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });
  await sendEmail({
    email: user?.email,
    subject: 'Password Reset Request',
    MailgenContent: forgotPasswordMailGen(
      `${process.env.FORGOT_PASSWORD_REDIRECT}/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(
      new ApiResponse(
        200,
        [],
        'Password Reset mail has been delivered to Your Email',
      ),
    );
});

const resetForgotPassword = asyncHandler(async (req, res) => {
  const { resetToken } = req.params;
  const { newPassword } = req.body;

  const hashedToken = crypto
    .createHash('sh256')
    .update(resetToken)
    .digest('hex');

  user = await User.findOne({
    forgotPasswordToken: hashedToken,
    forgotPasswordExpiry: { $gt: Date.now() },
  });

  if (!user) throw new ApiError(401, 'Token is Inavlid or Expired');

  user.forgotPasswordExpiry = undefined;
  user.forgotPasswordToken = undefined;
  user.password = newPassword;

  await user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, [], 'Password reset Succesfully'));
});

const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  const user = await User.findById(req.user?._id);
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) throw new ApiError(400, 'Password is Incorrect');

  user.password = newPassword;

  user.save({ validateBeforeSave: false });

  return res
    .status(200)
    .json(new ApiResponse(200, [], 'Password Changed Succesfully'));
});

export {
  registerUser,
  login,
  logoutUser,
  currentUser,
  verifyEmail,
  resendEmailVerification,
  forgotPasswordRequest,
  resetForgotPassword,
  changePassword,
  refreshAccessToken,
};
