const express = require("express");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const crypto = require("crypto");
const db = require("../db");

// Configure password authentication strategy.
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

// Configure session management.
passport.serializeUser((user, cb) => {
  process.nextTick(() => cb(null, { id: user.id, username: user.username }));
});

passport.deserializeUser((user, cb) => {
  process.nextTick(() => cb(null, { user }));
});

const router = express.Router();

// GET /login;
router.get("/login", (req, res) => {
  res.render("login");
});

//  POST /login/password
router.post(
  "/login/password",
  passport.authenticate("local", {
    successReturnToOrRedirect: "/",
    failureRedirect: "/login",
    failureMessage: true,
  })
);

// POST /logout
router.post("/logout", (req, res, next) => {
  req.logOut((err) => {
    if (err) return next(err);
    return res.redirect("/");
  });
});

module.exports = router;
