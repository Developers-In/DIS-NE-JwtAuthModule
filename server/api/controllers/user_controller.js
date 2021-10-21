const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const User = require('../models/user_model.js');
const bcrypt = require('bcrypt');


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
        const hashedPass = await bcrypt.hash(req.body.password, salt);

        const newUser = new User({
            _id: new mongoose.Types.ObjectId,
            username: username,
            email: email,
            password: hashedPass
        })
        const user = await newUser.save()
        //res.status(200).json(user._id);

        const verificationToken = user.generateVerificationToken();

        const url = `http://localhost:5000/api/verify/${verificationToken}`
        transporter.sendMail({
            to: email,
            subject: 'Verify Account',
            html: `Your account has been created successfully!! <br/><br/> Please click <a href = '${url}'>here</a> to confirm your email.`
        })
        return res.status(201).send({
            message: `Sent a verification email to ${email}`
        });
    } catch (err) {
        return res.status(500).send(err);
    }
}