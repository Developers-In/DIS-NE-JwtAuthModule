const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const UserSchema = mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    username: {
        type: String,
        required: true,
        unique: true,
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
    verified: {
        type: Boolean,
        required: true,
        default: false
    },
    verifiedLogin: {
        type: Boolean,
        required: true,
        default: false
    }
});
UserSchema.methods.generateVerificationToken = function () {
    const user = this;
    const verificationToken = jwt.sign(
        { ID: user._id },
        process.env.USER_VERIFICATION_TOKEN_SECRET,
        { expiresIn: "15m" }
    );
    return verificationToken;
};

module.exports = mongoose.model("User", UserSchema);