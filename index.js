/**
 * Create github repo project.
 * Set up application by:
 * 1. npm init
 * 2. npm install express
 * 3. Add *express root of project code* to index.js file
 * 4. node index.js -> to run the server
 * 5. npm install nodemon -g 
 * 6. nodemon index.js -> to run the server with nodemon
 * 7. npm install dotenv
 * 8. npm install joi
 * 
 */


//Express root of project code 
const express = require('express');
const app = express();

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


