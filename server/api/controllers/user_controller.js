const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user_model.js');

const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.EMAIL_USERNAME,
        pass: process.env.EMAIL_PASSWORD,
    },
});

exports.signup = async (req, res) => {
    const { username, email, password } = req.body

    if (!email || !username || !password) {
        return res.status(422).send({ message: "Username, Email, Password can not be empty." });
    }
    if (password.length < 8) {
        return res.status(422).send({ message: "password must be longer than 8 characters" });
    }
    try {
        const existingUser = await User.findOne({ email }).exec();
        if (existingUser) {
            return res.status(409).send({
                message: "This email already exists in the database."
            });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const newUser = new User({
            _id: new mongoose.Types.ObjectId,
            username: username,
            email: email,
            password: hashedPassword
        })
        const user = await newUser.save()

        const verificationToken = user.generateVerificationToken();

        const url = `http://localhost:5000/api/verify/${verificationToken}`
        transporter.sendMail({
            to: email,
            subject: 'Verify Account',
            html: `Your account has been created successfully!! <br/><br/> Please click <a href = '${url}'>here</a> to confirm your email.`
        })
        return res.status(200).json({ userId: user._id });
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.verify = async (req, res) => {
    const { token } = req.params
    if (!token) {
        return res.status(422).send({
            message: "Token is Missing"
        });
    }
    let payload = null
    try {
        payload = jwt.verify(
            token,
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
        user.verified = true;
        await user.save();
        res.status(200).send({
            message: "Account Verified"
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.signin = async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) {
        return res.status(422).send({
            message: "Email or Password can not be empty"
        });
    }

    try {
        const user = await User.findOne({ email }).exec();
        if (!user) {
            return res.status(400).json("Wrong Credentials")
        }
        const validated = await bcrypt.compare(req.body.password, user.password)
        if (!validated) {
            return res.status(400).json("Wrong Credentials")
        }

        if (!user.verified) {
            return res.status(403).send({
                message: "Please Verify your Account."
            });
        } else {
            const verificationToken = user.generateVerificationToken();

            const url = `http://localhost:5000/api/verifyLogin/${verificationToken}`
            transporter.sendMail({
                to: email,
                subject: 'Signin Verification',
                html: `Please click <a href = '${url}'>here</a> to verify your signin.`
            })
        }
        return res.status(200).send({
            message: `Verification token has sent to ${email}`
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.verifyLogin = async (req, res) => {
    const { token } = req.params
    if (!token) {
        return res.status(422).send({
            message: "Token is Missing"
        });
    }
    let payload = null
    try {
        payload = jwt.verify(
            token,
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
        user.verifiedLogin = true;
        await user.save();
        return res.redirect('/api/');
    } catch (err) {
        return res.status(500).send(err);
    }
}

exports.home = async (req, res) => {
    res.send("This is Home Page")
}

exports.logout = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        try {
            if (user.verifiedLogin) {
                user.verifiedLogin = false;
                await user.save();
                return res.status(200).send({
                    message: `User Loged out Successfully`
                });
            } else {
                return res.status(200).send({
                    message: `User has not logged in`
                });
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).json("User not found!");
    }
}

exports.forgotPassword = async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        try {
            if (user) {
                const verificationToken = user.generateVerificationToken();
                let id = user.id
                let email = user.email
                const url = `http://localhost:5000/api/resetPassword/${id}/${verificationToken}`
                transporter.sendMail({
                    to: email,
                    subject: 'Reset Password',
                    html: `Please click <a href = '${url}'>here</a> to reset your password.`
                })

                return res.status(200).send({
                    message: `Reset password link has sent to ${email}`
                });
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).json("User not found!");
    }
}

//GET
exports.resetPassword = async (req, res) => {
    const { id, verificationToken } = req.params;

    try {
        const user = await User.findById(id);
        try {
            if (user) {
                try {
                    payload = jwt.verify(
                        verificationToken,
                        process.env.USER_VERIFICATION_TOKEN_SECRET
                    );
                    return res.status(200).send({
                        message: `UserId is valid`, verificationToken: verificationToken
                    });
                } catch (err) {
                    return res.status(500).send(err);
                }
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).json("UserId is invalid!");
    }

}

//POST
exports.resetPasswordPost = async (req, res) => {
    const { id, verificationToken } = req.params;
    const { password, confirmPassword } = req.body;

    try {
        const user = await User.findById(id);
        try {
            if (user) {
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
                        res.status(404).json("Password invalid!");
                    } else {
                        const salt = await bcrypt.genSalt(10);
                        const hashedPass = await bcrypt.hash(req.body.confirmPassword, salt);
                        let newPassword = {}
                        newPassword.password = hashedPass

                        await User.findByIdAndUpdate(id, {
                            $set: newPassword
                        }, { upsert: true });
                        res.status(200).json("Password Updated Successfully");
                    }
                } catch (err) {
                    return res.status(500).send(err);
                }
            }
        } catch (err) {
            return res.status(500).send(err);
        }
    } catch (err) {
        res.status(404).json("UserId is invalid!");
    }

}