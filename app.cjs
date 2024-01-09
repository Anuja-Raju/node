const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

// Setup MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'customer',
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL: ', err);
  } else {
    console.log('Connected to MySQL');
  }
});

// Middleware to parse JSON and URL-encoded bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, etc.)
app.use(express.static('public'));




// SignUp endpoint
app.post('http://192.168.25.29/signup', async (req, res) => {
  const { user_id, password, confirm_password, user_type } = req.body;

  // Check if password and confirm_password match
  if (password !== confirm_password) {
    return res.status(400).send('Passwords do not match');
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if the user_id is unique
    const checkUserQuery = 'SELECT * FROM user WHERE user_id = ?';
    db.query(checkUserQuery, [user_id], async (error, results) => {
      if (error) {
        console.error('Error checking user:', error);
        return res.status(500).send('Internal Server Error');
      }

      if (results.length > 0) {
        return res.status(400).send('User already exists');
      }

      // Insert new user into the database with hashed password
      const insertUserQuery = 'INSERT INTO user (user_id, pass, user_type) VALUES (?, ?, ?)';
      db.query(insertUserQuery, [user_id, hashedPassword, user_type], (err) => {
        if (err) {
          console.error('Error inserting user:', err);
          return res.status(500).send('Internal Server Error');
        }

        res.redirect('/login'); // Redirect to login page after successful signup
      });
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    return res.status(500).send('Internal Server Error');
  }
});


// Login endpoint
app.post('http://192.168.25.29/login', (req, res) => {
  const { user_id, password } = req.body;

  // Check if user exists
  const loginUserQuery = 'SELECT * FROM user WHERE user_id = ?';
  db.query(loginUserQuery, [user_id], async (error, results) => {
    if (error) {
      console.error('Error checking login:', error);
      return res.status(500).send('Internal Server Error');
    }

    if (results.length === 1) {
      const hashedPassword = results[0].pass;

      // Compare the provided password with the hashed password in the database
      bcrypt.compare(password, hashedPassword, (compareErr, passwordMatch) => {
        if (compareErr) {
          console.error('Error comparing passwords:', compareErr);
          return res.status(500).send('Internal Server Error');
        }

        if (passwordMatch) {
          res.redirect('/data'); // Redirect to data page after successful login
        } else {
          res.status(401).send('Invalid credentials');
        }
      });
    } else {
      res.status(401).send('Invalid credentials');
    }
  });
});


// Endpoint to get the total businesses
app.get('/getTotalBusinesses', (req, res) => {
  const getTotalBusinessesQuery = 'SELECT SUM(OS_FTD) AS totalBusinesses FROM deposit_data';
  
  db.query(getTotalBusinessesQuery, (error, results) => {
    if (error) {
      console.error('Error getting total businesses:', error);
      return res.status(500).json({ error: 'Internal Server Error' });
    }

    const totalBusinesses = results[0].totalBusinesses || 0;
    res.json({ totalBusinesses });
  });
});



// Event listener for MySQL connection error
db.on('error', (err) => {
  console.error('MySQL connection error:', err);

  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    console.log('Attempting to reconnect to MySQL...');
    db.connect();
  } else {
    console.error('Unhandled MySQL connection error:', err);
    process.exit(1); // Exit the process on unhandled connection error
  }
});

// Global error handler for unhandled exceptions
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1); // Exit the process on unhandled exception
});

// Global error handler for unhandled Promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1); // Exit the process on unhandled rejection
});

// Start the server
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
