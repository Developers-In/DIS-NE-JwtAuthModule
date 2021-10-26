const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const UserSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    username: {
        type: String,
        required: true,
        minlength: 3,
        maxlength: 20
    },
    email: {
        type: String,
        required: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
    },
    verifiedSignUp: {
        type: Boolean,
        required: true,
        default: false
    },
}, { timestamps: true });

UserSchema.methods.generateVerificationToken = function () {
    const user = this;
    const verificationToken = jwt.sign(
        { ID: user._id },
        process.env.USER_VERIFICATION_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
    return verificationToken;
};

UserSchema.methods.generateForgotPasswordToken = function () {
    const user = this;
    const forgotToken = jwt.sign(
        { password: user.password },
        process.env.USER_VERIFICATION_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
    return forgotToken;
};

module.exports = mongoose.model("User", UserSchema);