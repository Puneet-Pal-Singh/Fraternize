const express = require("express");
const bcrypt = require("bcrypt");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../keys");
const User = require("../models/user");
const requireLogin = require("../middleware/requireLogin");

router.post("/signup", (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !name || !password) {
    res.status(422).json({ error: "Please fill all the fields" });
  } else {
    User.findOne({ email: email }) // returns a promise
      .then((savedUser) => {
        if (savedUser) {
          res
            .status(422)
            .json({
              error:
                "A user with same Email already exists. Please use a different Email id",
            });
        } else {
          bcrypt.hash(password, 12).then((hashedPassword) => {
            const user1 = new User({
              name, // condensed
              email, //condensed
              password: hashedPassword,
            });
            user1
              .save()
              .then((user) => {
                res.status(200).json({ msg: "User Added successfully" });
              })
              .catch((err) => {
                console.log(err);
              });
          });
        }
      })
      .catch((err) => {
        console.log(err);
      });
  }
});

router.post("/signin", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(422).json({ error: "Please fill the required fields!" });
  }
  User.findOne({ email: email })
    .then((savedUser) => {
      if (!savedUser) {
        return res.status(422).json({ error: "Invalid Email!!" });
      }
      bcrypt
        .compare(password, savedUser.password) //returns a boolean value
        .then((doMatch) => {
          if (doMatch) {
            const token = jwt.sign({ _id: savedUser._id }, JWT_SECRET); //token is generated with the user_id and the secret key
            const { _id, email, name, followers, following } = savedUser; //  destructure these things from the savedUser
            return res.json({
              token,
              user: { _id, email, name, followers, following },
            }); //return this in Developer Options > Application
          } else {
            return res.status(422).json({ error: "Invalid Email or password" });
          }
        });
    })
    .catch((err) => console.log(err));
});

module.exports = router;
