// Load utility functions (e.g., include) from utils.js
require("./utils.js");

// Load environment variables from .env file
require("dotenv").config();

// Import required modules
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo"); // session store for MongoDB
const bcrypt = require("bcrypt"); // for password hashing
const Joi = require("joi"); // for input validation

const saltRounds = 11; // bcrypt salt rounds for hashing passwords
const app = express(); // Create an Express application
const port = process.env.PORT || 8000; // Port for the server

// Set the session expiration time to 1 hour
const expireTime = 60 * 60 * 1000;

// Secret section for sensitive information
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

// Connect to MongoDB using custom 'include' from utils.js
var { database } = include("databaseConnection");

// Connect to the MongoDB database and collection
const userCollection = database.db(mongodb_database).collection("users");

// Middleware to parse JSON and URL-encoded data (for form submissions)
app.use(express.urlencoded({ extended: false }));

// Create MongoDB session store
// This is used to store session data in MongoDB instead of memory
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret, //encrypt session data
    },
});

// Middleware to handle sessions
// This uses the MongoDB session store created above and the session secret is used to sign the session ID cookie
app.use(
    session({
        secret: node_session_secret, //session encryption key
        store: mongoStore, // Store sessions in MongoDB
        saveUninitialized: false, // don't save empty sessions
        resave: true, //save session even if unmodified
    })
);

/**
 * Middleware to check if the user is authenticated
 */
function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req, res, next) {
    if (isValidSession(req)) {
        next();
    } else {
        const errorType = "You're not logged in.";
        res.render("oops", { errorType });
        console.log("Unauthenticated access attempt.");
    }
}

function isAdmin(req) {
    if (req.session.userType == "admin") {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("oops", {
            errorType: "You're not Authorized for this page.",
        });
        console.log("Unauthorized access attempt.");
        return;
    } else {
        next();
    }
}

app.post("/promote", async (req, res) => {
    const email = req.body.email;
    await userCollection.updateOne({ email }, { $set: { userType: "admin" } });
    res.redirect("/admin");
    console.log("User promoted to admin.");
});

app.post("/demote", async (req, res) => {
    const email = req.body.email;
    await userCollection.updateOne({ email }, { $set: { userType: "user" } });
    res.redirect("/admin");
    console.log("User demoted to user.");
});

/**
 * EJS template engine setup
 * EJS routing
 */
app.set("view engine", "ejs");

app.use(express.static(__dirname + "/public"));

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get("/dogs", sessionValidation, (req, res) => {
    const dogImage = [
        "cool-kenai.jpg",
        "curious-kenai.jpg",
        "sleepy-kenai.jpg",
        "kenai4.jpg",
        "kenai5.jpg",
        "kenai6.jpg",
        "kenai7.jpg",
        "kenai8.jpg",
        "kenai9.jpg",
        "kenai10.jpg",
    ];
    const name = req.session.name;

    res.render("dogs", { dogImage: dogImage, name: name });
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection
        .find()
        // .project({ name: 1, userType: 1 })
        .toArray();
    res.render("admin", { users });
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.render("logout");
});

// Handle login form submission
//// This route is used to authenticate the user when they log in
app.post("/loggingIn", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    // Validate email and password using Joi
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);

        const errorType = "Invalid email.";
        res.render("oops", { errorType });
        return;
    }

    // find user in the MongoDB collection by email
    const result = await userCollection
        .find({ email: email })
        .project({ email: 1, password: 1, _id: 1, name: 1, userType: 1 })
        .toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");

        const errorType = "User not found.";
        res.render("oops", { errorType });
        return;
    }

    // compare submitted password with stored hashed password
    // If the password matches, set the session variables and redirect to the loggedIn page
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime; // set session expiration time to 1 hour
        req.session.name = result[0].name; // store the user's name in the session
        req.session.userType = result[0].userType;

        res.redirect("/dogs");
        // res.render("dogs", { name: req.session.name }, { userType: req.session.userType });
        return;
    } else {
        console.log("incorrect password");

        const errorType = "Incorrect password.";
        res.render("oops", { errorType });
        return;
    }
});

// route to handle form submission from signUp page
app.post("/signingUp", async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    // Validate email and password using Joi
    // This ensures that the email is alphanumeric and has a maximum length of 20 characters
    const schema = Joi.object({
        email: Joi.string().max(20).required(),
        password: Joi.string().max(20).required(),
    });

    // Validate the input data against the schema
    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        const errorType = "Invalid email or password. Only use 20 characters.";
        res.render("oops", { errorType });
        return;
    }

    // Hash the password using bcrypt before storing it in the database
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert the new user into the MongoDB collection
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        userType: "user",
    });
    console.log("Inserted user");

    res.render("login");
    return;
});

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log("Server is running on port: " + port);
});
