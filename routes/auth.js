const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const crypto = require("crypto");
const db = require("../db");

const router = express.Router();

passport.use(
  new LocalStrategy((username, passwod, cb) => {
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
      if (err) return cb(err);
      if (!row) return cb(null, false, { message: "Incorrect username or password." });

      crypto.pbkdf2(passport, row.salt, 310000, "sha256", (err, hashedPassword) => {
        if (err) return cb(err);
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) return cb(null, false, { message: "Incorrect username or password." });
      });
      return cb(null, row);
    });
  })
);

router.get("/login", (req, res) => {
  res.render("login");
});
router.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

module.exports = router;
