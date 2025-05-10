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
 * EJS template engine setup
 * EJS routing
 */
app.set("view engine", "ejs");

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get("/dogs", (req, res) => {
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
        "kenai10.jpg"
    ];
    res.render("dogs", { dogImage });
});

app.get("/admin", (req, res) => {
    res.render("admin");
});

// app.get("/members", (req, res) => {
//     if (!req.session.authenticated) {
//         res.render("members", { authenticated: false });
//     } else {
//         res.render("members", { authenticated: true });
//     }
// });

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.render("logout");
});

app.get("*dummy", (req, res) => {
    res.status(404);
    res.render("404");
});

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
        res.redirect("/login");
    }
}

function isAdmin(req) {
    if (req.session.user_type == "admin") {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", { error: "Not Authorized" });
        return;
    } else {
        next();
    }
}
/**
 * End of authentication/authorization middleware
 */

// // app.get('/', (req, res) => {

//     if(req.query.action === 'login') {
//         res.redirect('/login'); // Redirect to the login page if the action is 'login'
//         return;
//     } else if(req.query.action === 'signup') {
//         res.redirect('/signup'); // Redirect to the signup page if the action is 'signup'
//         return;
//     }

//     res.send(`
//         <body>
//             <div>
//                 <form action="/" method="get" style="display: inline;">
//                     <button type="submit" name="action" value="login">Log in</button>
//                 </form>
//                 <form action="/" method="get" style="display: inline;">
//                     <button type="submit" name="action" value="signup">Sign Up</button>
//                 </form>
//             </div>
//         </body>
//     `);
// });

// // login route to display a form for logging in
// app.get('/login', (req,res) => {
//     var html = `
//     Log In
//     <form action='/loggingIn' method='post'>
//         <input name='email' type='text' placeholder='email'>
//         <input name='password' type='password' placeholder='password'>
//         <button type="submit" name="action" value="submit">Submit</button>
//     </form>
//     `;
//     res.send(html);
// });

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

        // var html = `
        // <%- include('templates/header') %>
        //     <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
        //         <p style="color: black; font-family: Arial, sans-serif; font-size: 18px; margin-bottom: 15px;">
        //             Ooops! Invalid email. Please try again.
        //         </p>
        //         <form action="/login" method="get">
        //             <button
        //             type="submit"
        //             name="action"
        //             value="submit"
        //             style="padding: 10px 20px; background-color: olivedrab; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;"
        //             >
        //             Try Again
        //             </button>
        //         </form>
        //         </div>
        //     <%- include('templates/footer') %>
        // `;
        // res.send(html);

        const errorType = "Invalid email.";
        res.render("oops", { errorType });
        return;
    }

    // find user in the MongoDB collection by email
    const result = await userCollection
        .find({ email: email })
        .project({ email: 1, password: 1, _id: 1, name: 1 })
        .toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");

        // var html = `
        // <%- include('templates/header') %>
        //     <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
        //         <p style="color: black; font-family: Arial, sans-serif; font-size: 18px; margin-bottom: 15px;">
        //             Ooops! User not found. Please try again.
        //         </p>
        //         <form action="/login" method="get">
        //             <button
        //             type="submit"
        //             name="action"
        //             value="submit"
        //             style="padding: 10px 20px; background-color: olivedrab; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;"
        //             >
        //             Try Again
        //             </button>
        //         </form>
        //         </div>
        //     <%- include('templates/footer') %>
        // `;
        // res.send(html);

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

        res.redirect("/members");
        return;
    } else {
        console.log("incorrect password");
        // var html = `
        // <%- include('templates/header') %>
        //     <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
        //         <p style="color: black; font-family: Arial, sans-serif; font-size: 18px; margin-bottom: 15px;">
        //             Ooops! Incorrect password. Please try again.
        //         </p>
        //         <form action="/login" method="get">
        //             <button
        //                 type="submit"
        //                 name="action"
        //                 value="submit"
        //                 style="padding: 10px 20px; background-color: olivedrab; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;"
        //                 >
        //             Try Again
        //             </button>
        //         </form>
        //     </div>
        //     <%- include('templates/footer') %>
        // `;
        // res.send(html);

        const errorType = "Incorrect password.";
        res.render("oops", { errorType });
        return;
    }
});

// // Signup route to display a form for creating a new user
// //// This route is used to create a new user in the MongoDB database
// app.get("/signup", (req, res) => {
//     var html = `
//     Sign Up
//     <form action='/signingUp' method='post'>
//     <input name='name' type='text' placeholder='Your name'>
//     <input name='email' type='text' placeholder='email'>
//     <input name='password' type='password' placeholder='password'>
//     <button>Submit</button>
//     </form>
//     `;
//     res.send(html);
// });

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
        res.redirect("/signup");
        var html = `
        <%- include('templates/header') %>
            <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
                <p style="color: black; font-family: Arial, sans-serif; font-size: 18px; margin-bottom: 15px;">
                    Ooops! Invalid email and/or password. Please try again.
                </p>
                <form action="/signup" method="get">
                    <button 
                    type="submit" 
                    name="action" 
                    value="submit" 
                    style="padding: 10px 20px; background-color: olivedrab; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;"
                    >
                    Try Again
                    </button>
                </form>
                </div>
            <%- include('templates/footer') %>
        `;
        res.send(html);
        return;
    }

    // Hash the password using bcrypt before storing it in the database
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // insert the new user into the MongoDB collection
    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
    });
    console.log("Inserted user");

    res.redirect("/members");
});

app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        var html = `
        <%- include('templates/header') %>
            <div style="display: flex; flex-direction: column; align-items: center; margin-top: 40px;">
                <p style="color: black; font-family: Arial, sans-serif; font-size: 18px; margin-bottom: 15px;">
                    Please Log In to access this page.
                </p>
                <form action="/login" method="get">
                    <button 
                    type="submit" 
                    name="action" 
                    value="submit" 
                    style="padding: 10px 20px; background-color: olivedrab; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer;"
                    >
                    Log In
                    </button>
                </form>
                </div>
            <%- include('templates/footer') %>
        `;
        res.send(html);
        return;
    }

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
    const randomIndex = Math.floor(Math.random() * dogImage.length);
    const randomDogImage = dogImage[randomIndex];

    var html = `
        <%- include('templates/header') %>
        <body>
            <h1>Hello, ${req.session.name}!</h1>
            <img src="/${randomDogImage}" style="height:80vh;">
            <form action="/logout" method="get">
                <button type="submit">Logout</button>
            </form>
        </body>
        <%- include('templates/footer') %>
    `;
    res.send(html);
    return;
});

// // Logout route to destroy the session and redirect to the logout page
// app.get("/logout", (req, res) => {
//     req.session.destroy();

//     var html = `
//     <%- include('templates/header') %>
//     <body>
//         <div>
//             <h1>You are logged out.</h1>
//             <form action="/" method="get">
//                 <button type="submit">Return Home</button>
//             </form>
//         </div>
//     </body>
//     <%- include('templates/footer') %>
//     `;
//     res.send(html);
// });

// Serve static files from the public directory
app.use(express.static(__dirname + "/public"));

// // Handle any unmatched routes with a 404 error
// app.get("*dummy", (req, res) => {
//     res.status(404);
//     res.send("Page not found :( - 404");
// });

app.listen(port, () => {
    console.log("Server is running on port: " + port);
});
