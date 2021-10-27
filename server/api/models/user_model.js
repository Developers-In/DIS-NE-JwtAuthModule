const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const UserSchema = mongoose.Schema({
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

module.exports = mongoose.model("User", UserSchema);