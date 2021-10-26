const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user_model.js');
const { authSchema, signInSchema } = require('../validators/validator.js')

const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
    },
});

exports.signup = async (req, res) => {

    const { value, error } = authSchema.validate(req.body);

    if (error) {
        return res.status(400).send(error.details[0].message)
    } else {
        const existingUser = await User.findOne({ email: value.email });
        if (existingUser) {
            return res.status(409).send({
                message: "This email already exists in the database."
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(value.password, salt);

        const newUser = new User({
            _id: new mongoose.Types.ObjectId,
            username: value.username,
            email: value.email,
            password: hashedPassword
        })
        const user = await newUser.save()

        const verificationToken = user.generateVerificationToken();

        const url = `http://localhost:5000/api/verifySignUp/${verificationToken}`
        transporter.sendMail({
            to: value.email,
            subject: 'Account Verification',
            html: `Your account has been created successfully!! <br/><br/> Please click <a href = '${url}'>here</a> to confirm your email.`
        })
        return res.status(200).json({ userId: user._id });
    }
}

exports.verifySignUp = async (req, res) => {
    const { verificationToken } = req.params;
    if (!verificationToken) {
        return res.status(422).send({
            message: "Token is Required"
        });
    }
    let payload = null
    try {
        payload = jwt.verify(
            verificationToken,
            process.env.USER_VERIFICATION_TOKEN_SECRET
        );
    } catch (err) {
        return res.status(500).send(err);
    }
    try {
        const user = await User.findOne({ _id: payload.ID }).exec();
        if (!user) {
            return res.status(404).send({
                message: "User does not  exists"
            });
        }
        user.verifiedSignUp = true;
        user.verifiedSignIn = true;
        await user.save();
        res.status(200).send({
            message: "Account is Verified"
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.signin = async (req, res) => {

    const { value, error } = signInSchema.validate(req.body);

    if (error) {
        return res.status(400).send(error.details[0].message)
    } else {
        try {
            const user = await User.findOne({ email: value.email }).exec();
            if (!user) {
                return res.status(400).json("Invalid Credentials")
            }
            const validated = await bcrypt.compare(value.password, user.password)
            if (!validated) {
                return res.status(400).json("Invalid Credentials")
            }

            if (!user.verifiedSignUp) {
                return res.status(403).send({
                    message: "Please Verify your Account."
                });
            } else {
                const verificationToken = user.generateVerificationToken();

                const url = `http://localhost:5000/api/verifySignIn/${verificationToken}`
                transporter.sendMail({
                    to: value.email,
                    subject: 'Signin Verification',
                    html: `Please click <a href = '${url}'>here</a> to verify your signin.`
                })
                return res.status(200).send({
                    message: `Verification token has sent to ${value.email}`
                });
            }

        } catch (err) {
            return res.status(500).send(err);
        }
    }
}

exports.verifySignIn = async (req, res) => {
    const { verificationToken } = req.params
    if (!verificationToken) {
        return res.status(422).send({
            message: "Token is Required"
        });
    }
    let payload = null
    try {
        payload = jwt.verify(
            verificationToken,
            process.env.USER_VERIFICATION_TOKEN_SECRET
        );
    } catch (err) {
        return res.status(500).send(err);
    }
    try {
        const user = await User.findOne({ _id: payload.ID }).exec();
        if (!user) {
            return res.status(404).send({
                message: "User does not  exists"
            });
        }
        return res.status(200).json({ message: "User signed in successfully" })
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.forgotPassword = async (req, res) => {
    try {
        const user = await User.findById(req.params.userId);
        try {
            if (user) {
                const verificationToken = user.generateForgotPasswordToken();
                const url = `http://localhost:5000/api/resetPassword/${user.id}/${verificationToken}`
                transporter.sendMail({
                    to: user.email,
                    subject: 'Reset Password',
                    html: `Please click <a href = '${url}'>here</a> to reset your password.`
                })
                return res.status(200).send({
                    message: `Reset password link has sent to ${user.email}`
                });
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).send({ message: "User does not exists!" });
    }
}

//GET
exports.resetPassword = async (req, res) => {
    const { userId, verificationToken } = req.params;

    try {
        const user = await User.findById(userId);
        try {
            if (user) {
                try {
                    payload = jwt.verify(
                        verificationToken,
                        process.env.USER_VERIFICATION_TOKEN_SECRET
                    );
                    return res.status(200).send({
                        message: `UserId is valid`
                    });
                } catch (err) {
                    return res.status(500).send(err);
                }
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).send({
            message: `UserId is valid`
        });
    }

}

//POST
exports.resetPasswordPost = async (req, res) => {
    const { userId, verificationToken } = req.params;
    const { password, confirmPassword } = req.body;
    
    try {
        const user = await User.findById(userId);
        
        try {
            if (user) {
                console.log(user)
                try {
                    payload = jwt.verify(
                        verificationToken,
                        process.env.USER_VERIFICATION_TOKEN_SECRET
                    );

                    const conditionsArray = [
                        password !== confirmPassword,
                        confirmPassword.length < 8,
                    ]

                    if (conditionsArray.includes(true)) {
                        res.status(404).send({message: "Password is invalid!"});
                    } else {
                        const salt = await bcrypt.genSalt(10);
                        const hashedPass = await bcrypt.hash(req.body.confirmPassword, salt);
                        let newPassword = {}
                        newPassword.password = hashedPass

                        await User.findByIdAndUpdate(userId, {
                            $set: newPassword
                        }, { upsert: true });
                        res.status(200).send({message: "Password updated successfully!"});
                    }
                } catch (err) {
                    return res.status(500).send(err);
                }
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).send({message: "UserId is invalid!"});
    }
}

exports.resendVerificationToken = async (req, res) => {
    const { userId } = req.params;

    try {
        const user = await User.findById(userId);
        try {
            if (user.verifiedSignUp) {
                const verificationToken = user.generateVerificationToken();
                let email = user.email;
                const url = `http://localhost:5000/api/verifySignIn/${verificationToken}`
                transporter.sendMail({
                    to: email,
                    subject: 'Signin Verification',
                    html: `Please click <a href = '${url}'>here</a> to verify your signin.`
                })
                return res.status(200).send({
                    message: `verification email has sent to ${email}`
                });
            } else {
                res.status(404).json("Please verify your account first")
            }
        } catch (err) {
            res.status(404).json(err.message)
        }
    } catch (err) {
        res.status(404).json("UserId is invalid!");
    }
}