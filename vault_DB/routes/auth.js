const express = require("express");
const router = express.Router();
const User = require("/Users/anushkashelke/Desktop/vault_password/vault_DB/models/user.js");

router.post("/register", async (req, res) => {

    const { email, password } = req.body;

    const user = new User({
        email,
        password
    });

    await user.save();

    res.json({ message: "User registered" });

});

module.exports = router;