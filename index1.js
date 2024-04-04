import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(bodyParser.urlencoded({ extended: true })); //parse incoming request bodies, "true" to deal with complex algorithm ( nested objects)
app.use(express.static("public")); //serve static files from "public" folder

app.use(
  session({
    //initiate session
    secret: "TOPSECRETWORD",
    resave: false, // dont save session if unmodified,
    saveUnitilized: true, // always create session to ensure login
    cookie: {
      maxAge: 1000 * 60 * 60 * 24, //set time for session expiration
    },
  })
);

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secret",
  password: "Lenhuy@1996",
  port: 5432,
});

db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", (req, res) => {
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
app.post("/register", async (req, res) => {
  const email = req.body.username; //parse email from form based on name attribute
  const password = req.body.password;

  try {
    //get all info from database associate with the email input from user
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("User is already exist.");
      res.redirect("/login");
    } else {
      //hashing password, save it in database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error handling password: ", err);
        } else {
          console.log("hashed password: ", hash);
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );

          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("Success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

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
            console.log("Error comparing password: ", err);
          } else {
            if (valid) {
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
  console.log(`Server is running on port ${port}`);
});
