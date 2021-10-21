const express = require("express");
const app = express();
require('dotenv').config();
const mongoose = require("mongoose");

const PORT = process.env.PORT || 5000;
const URL = process.env.MONGODB_URL;

mongoose.connect(URL, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useUnifiedTopology: true,
    useFindAndModify: false
}).then(() => {
    console.log("Successfully connected to mongoDB.");
}).catch((err) => {
    console.log("Error connecting to mongoDB.", err);
});

app.use(express.json());

app.use('/api', require('./api/routes/routes.js'));

app.listen(PORT, () => {
    console.log("Listening on port: " + PORT);
});