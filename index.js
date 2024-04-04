import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config(); // intialise the dotenv package

app.use(bodyParser.urlencoded({ extended: true })); // parse form data
app.use(express.static("public")); //serve static files from public folder

app.use(
  session({
    secret: process.env.TOP_SECRET, // secret key
    resave: false, // don not save session if unmodified
    saveUninitialized: true, //always create session to ensure login
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, // set time for session to expire
    },
  })
);

app.use(passport.initialize()); //initialize passport, always before passport.session()
app.use(passport.session()); //use passport session

const db = new pg.Client({
  user: process.env.TOP_USER,
  host: process.env.TOP_HOST,
  database: process.env.TOP_DATABASE,
  password: process.env.TOP_PASSWORD,
  port: process.env.TOP_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  // route to login page
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err); //pas control into the next error handler, return to the previous page
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
  //console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//user register, hash the password and save it in database
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
      req.redirect("/login");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

//verify the password and username, compare the password input from user and th stored password in database
passport.use(
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            //error with password check
            console.error("Error comparing password: ", err);
          } else {
            if (valid) {
              //passed password check
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (err) {
      console.log(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});
passport.deserializeUser((user, cb) => {
  cb(null, user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
