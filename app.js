import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import passport from "passport";
import bcrypt, { compare } from "bcrypt";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth20";
import cors from "cors";
import MagicLoginStrategy from "passport-magic-login"
const LocalStrategy = Strategy.Strategy;
import cookieParser from "cookie-parser";
import nodemailer from "nodemailer";
import {mongoDBURL,Google_Client_Id,Google_Client_Secret,GmailPass} from "./config"

const app = express();
const PORT = 5555;



app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: "any long secret key",
    resave: false,
    saveUninitialized: false,
  })
);

// Initializing Passport
app.use(passport.initialize());

// Starting the session
app.use(passport.session());

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
  })
);

// to use all the http methods in routes we will use the 'use' middleware

mongoose
  .connect(mongoDBURL)
  .then(() => {
    console.log("App connected to DataBase");
    app.listen(PORT, () => {
      console.log(`App is listening to port: ${PORT}`);
    });
  })
  .catch((error) => {
    // console.log(error);
  });

const UserSchema = new mongoose.Schema({
  name: String,
  username: String,
  password: String,
  picture: String,
});
const User = mongoose.model("User", UserSchema);

passport.use(
  new LocalStrategy(async function (username, password, done) {
    const user = await User.findOne({ username });
    if (!user) {
      return done(null, false);
    }
    const userValid = await compare(password, user.password);
    if (!userValid) {
      return done(null, false);
    }
    return done(null, user);
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  User.findById(userId)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => done(err));
});

passport.use(
  new GoogleStrategy.Strategy(
    {
      clientID: Google_Client_Id,
      clientSecret: Google_Client_Secret,
      callbackURL: "/google/callback",
    },
    async function (accessToken, refreshToken, profile, cb) {
      // console.log(profile);
      const user = profile._json;
      // console.log(user);
      const foundUser = await User.findOne({ username: user.sub });
      if (!foundUser) {
        const newUSer = await User.create({
          name: user.name,
          username: user.sub,
          picture: user.picture,
        });
        cb(null, newUSer);
      } else {
        cb(null, foundUser);
      }
    }
  )
);

const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: true,
  auth: {
    // TODO: replace `user` and `pass` values from <https://forwardemail.net>
    user: "modiniraj1034",
    pass: GmailPass,
  },
});


  const sendEmail = async (obj) => {
    try{
      const info = await transporter.sendMail({
        from: '" Merina Admin " <janis.lehner72@ethereal.email>',
        to: obj.to,
        subject:'Magic Link For Authentication',
        html: obj.html,
      });
      return (info)
    }catch(err){
      throw new Error(err)
    }
  }




const magicLogin = new MagicLoginStrategy.default({
  // Used to encrypt the authentication token. Needs to be long, unique and (duh) secret.
  secret: "Special Magic Login Strategy",

  // The authentication callback URL
  callbackUrl: "/magiclogin/callback",


  sendMagicLink: async (destination, href) => {
    await sendEmail({
      to: destination,
      html: `<b>Click this link to finish logging in: <a href="http://localhost:5555${href}">Login</a></b>`
    })
  },


  verify: async (payload, callback) => {

    try{
      const foundUser = await User.findOne({username:payload.destination});
      if(!foundUser){
        callback({error:"user not found"})
      }
      else{
        callback(null,foundUser);
      }
    }
    catch(err){
      callback(err)
    }
  },


  jwtOptions: {
    expiresIn: "2 days",
  }
})

// Add the passport-magic-login strategy to Passport
passport.use(magicLogin)


// This is where we POST to from the frontend
app.post("/magiclogin", magicLogin.send);

// // The standard passport callback setup
app.get("/magiclogin/callback", passport.authenticate("magiclogin"),(req,res)=>{
  res.redirect("http://localhost:3000")
});


app.get("/", (req, res) => {
  if (req.isAuthenticated()) res.send("Authenticated");
  else res.send("Not Authenticated");
});

app.post("/register", async (req, res) => {
  const { name, username, password } = req.body;
  // console.log(req.body);
  const foundUser = await User.findOne({ username: username });

  if (foundUser) {
    res.status(409).json({ error: "User Found" });
    return;
  }

  const hashedPassword = await bcrypt.hash(password, 11);

  await User.create({
    name,
    username,
    password: hashedPassword,
  });

  res.status(200).json({ msg: "registered Succesfully" });
});

app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  async function (req, res) {
    const user = { username: req.user.username, name: req.user.name };
    // const token = jwt.sign(user,"JWT_SECRET", {expiresIn: "1d"})
    // console.log(req.cookies)
    res
      .status(200)
      // .cookie("authToken",token)
      .json({
        message: "Login successful",
        success: true,
      });
  }
);



app.get("/login/failed", (req, res) => {
  res.status(401)({});
});

app.get("/login/success", (req, res) => {
  // console.log("hello");
  // console.log(req.user);
  if (req.isAuthenticated()) {
    const user = { name: req.user.name };
    if (req.user.picture) user.picture = req.user.picture;
    // const token = jwt.sign(user,"JWT_SECRET", {expiresIn: "1d"})
    // console.log(req.cookies)
    res
      .status(200)
      // .cookie("authToken",token)
      .json({
        success: true,
        user,
      });
  } else {
    res.status(401).json({ msg: "invalid token" });
  }
});

app.get("/google", passport.authenticate("google", { scope: ["profile"] }));

app.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: "http://localhost:3000",
    failureRedirect: "/login/failed",
  })
);

app.get("/logout", async (req, res) => {
  await req.logout((err)=>{});
  // req.session = null
  res.clearCookie("connect.sid",{path:"/",httpOnly:true})
  res.status(200).json({msg:"logout Succesfull"})
//   req.session.destroy(function (err) {
//     res.status(200).json({msg:"logout Succesfull"}); //Inside a callback… bulletproof!
// });
});