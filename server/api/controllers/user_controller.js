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
        return res.status(200).send({
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
        }
        return res.status(200).send({
            message: "User logged in"
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}