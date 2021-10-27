const Joi = require('joi');

const authSchema = Joi.object({
    username: Joi.string()
        .alphanum()
        .min(3)
        .max(20)
        .required(),

    password: Joi.string().min(8).required()
        //.pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$')),
        .pattern(new RegExp('^[a-zA-Z0-9@$!%*?&]{8,20}$')),

    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
}).options({abortEarly: false})


const signInSchema = Joi.object({

    email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } }),
    
    password: Joi.string().min(8).required()
        .pattern(new RegExp('^[a-zA-Z0-9@$!%*?&]{8,20}$')),

    
}).options({abortEarly: false})

module.exports = {authSchema, signInSchema};