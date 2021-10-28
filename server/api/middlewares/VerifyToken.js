const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.token;
    if (authHeader) {
        const token = authHeader.split(" ")[1]
        jwt.verify(token, process.env.USER_VERIFICATION_TOKEN_SECRET, (err, user) => {
            if (err) {
                res.status(403).send({ message: "Token is invalid!" })
            } else {
                req.user = user;
                next()
            }
        })
    } else {
        return res.status(401).send({ message: "User is not authenticated!" })
    }
}

module.exports = { verifyToken }