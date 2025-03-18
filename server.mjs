import express from "express"; // for transactions
import pg from "pg"; // for pg connection
import cors from "cors"; // access control optiona
import bcrypt from "bcryptjs"; // for handling user passwords
import jwt from 'jsonwebtoken'; // for handling JWT for authorization

/*
This section is for pg connection handling.
This code will instantiate the connection to pg server.
*/

const app = express();
const port = 3000;
const { Pool } = pg;

const pool = new Pool({
    user: 'postgres.yzktumgeariddxkxyydp',
    host: 'aws-0-us-east-1.pooler.supabase.com',
    database: 'postgres',
    password: 'V21Z4YH0iARwVAoM',
    port: 6543,
    idleTimeoutMillis: 300
});

/*
const corsOptions ={
   origin: '*', 
   credentials: true, //access-control-allow-credentials:true
   optionSuccessStatus: 200,
}
app.use(cors(corsOptions));
*/

app.use(express.json()); // allows for json post requests

/*
This section is for password encryption handling.
User passwords will be encrypted in the DB.
*/

// this async function will provide an encryption
async function encryptPassword(password) {
  const salt = await bcrypt.genSalt(10); // Defines how much time is needed to calculate a single bcrypt hash.              
  try {                  // The higher the cost factor, the more hashing rounds are done.
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  } catch (error) {
    console.error("Error encrypting password:", error);
    throw error;
  }
}

// this async function will compare hash passwords
async function comparePassword(password, hashedPassword) {
    try {
      const isMatch = await bcrypt.compare(password, hashedPassword);
      return isMatch;
    } catch (error) {
          console.error("Error comparing passwords:", error);
          throw error;
    }
}

/*
This section is for JWT.
This will allow user authorization for DB access.
This JWT is generated after sign-in.
This JWT is used during the upvote/heart system and for caption uploads.
JWT not required for other DB operations.
*/

const secretKey = 'IskanderCaptionContest748!';

// below creates the JWT
// and houses payload (returned data)
function createToken(userDB) {
    const token = jwt.sign({
        username: userDB // put username from DB here
    }, secretKey, { expiresIn: '1h' });

    return token;
}

// below code verifies the JWT
// should be used in upvotes and caption uploads
/*
jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      console.log('Token is invalid');
    } else {
      console.log('Decoded Token:', decoded);
    }
});

// this get request will test print a JWT, if successful
app.get('/jwt', async (req, res) => {
    
    const token = jwt.sign({
        username: 'KingJoe'// put username from DB here
    }, secretKey, { expiresIn: '1h' });

    res.send(token);
});

// this get request will test JWT provided

app.get('/jwt/clean', async (req, res) => {
    
    const encToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IktpbmdKb2UiLCJpYXQiOjE3NDIyNTI3MzYsImV4cCI6MTc0MjI1NjMzNn0.c8RGR6BGcf5-kCn_DVqp62QjGdRer5WkNZi6n3xeRXc';
   
    jwt.verify(encToken, secretKey, (err, decoded) => {
        if (err) {
          console.log('Token is invalid');
          res.send('Failed');
        } else {
          console.log('Decoded Token:', decoded);
          res.send(decoded);
        }
    });

});
*/

/*
This section is for image handling.
It will connect with the captions later on.
*/

// this function will query and get all the images available
async function graballimages() {
    const dbclient = await pool.connect();
    try {
        dbclient.query('BEGIN');
        let imageURLs = [];
        const query = 'SELECT imageurl FROM images';
        const result = await dbclient.query(query);
        
        for(let i = 0; i < result.rows.length; i++) {
            imageURLs.push(result.rows[i].imageurl);
        }

        return imageURLs;
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// this get request will provide the imageURLs from the database!
app.get('/graballimages', async (req, res) => {
    const imageURLs = await graballimages();
    res.send(imageURLs);
});

/*
This section is for user handling.
It will consist of user sign ins and sign ups.
*/

// function to check if user exists
async function checkifexists(username, email) {
    // query to check if a user exists
    const dbclient = await pool.connect();
    try {
        await dbclient.query('BEGIN');
        let query = 'SELECT email FROM users WHERE email = $1';
        let result = await dbclient.query(query, [email]);

        if (result.rows.length === 0) { //meaning unique email address
            query = 'SELECT username FROM users WHERE username = $1';
            result = await dbclient.query(query, [username]);
            if (result.rows.length === 0) { //meaning unique username
                return true;
            }
        }

        return false;
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// function to insert new user into db
// will encrypt passwords
async function insertnewuser(username, password, email) {
    const dbclient = await pool.connect();
    try {
        await dbclient.query('BEGIN');
        const now = new Date(); // set and convert timestamp
        const timestamp = now.toISOString().slice(0, 19).replace('T', ' ');
        const ePassword = await encryptPassword(password); // encrypt password
        
        const query = 'INSERT INTO users (username, password, email, registeredat, lastlogin) VALUES ($1, $2, $3, $4, $5)';
        await dbclient.query(query, [username, ePassword, email, timestamp, timestamp]);
        await dbclient.query('COMMIT');

        return true;
    } catch (e) {
        await dbclient.query('ROLLBACK')
        throw e
    } finally {
        dbclient.release()
    }
}

// function to sign in a user based on email and password
async function signin(email, password) {
    // query to check if a user exists
    const dbclient = await pool.connect();
    try {
        await dbclient.query('BEGIN');
        let query = 'SELECT password FROM users WHERE email = $1';
        let result = await dbclient.query(query, [email]);
        
        // check hash password against hashed user pw
        const isPasswordCorrect = await comparePassword(password, result.rows[0].password);
        if (isPasswordCorrect) {
            query = 'SELECT username FROM users WHERE email = $1';
            result = await dbclient.query(query, [email]);
            const token = createToken(result.rows[0].username);
            return token;
        }

        return isPasswordCorrect;
        
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// function to sign in a user based on email and password
async function collectusername(email) {
    // query to grab username given an email
    const dbclient = await pool.connect();
    try {
        await dbclient.query('BEGIN');
        const query = 'SELECT username FROM users WHERE email = $1';
        const result = await dbclient.query(query, [email]);
        let username = [];
        username.push(result.rows[0].username);
        return username;
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// this get request will check if a user exists
app.post('/checkifexists', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;

    // fail if blanks
    if (username.trim().length === 0 || email.trim().length === 0) {
        res.send(false);
    } else {
        if (await checkifexists(username, email)) {
            res.send({ message: 'Success' });
        } else {
            res.send({ message: 'Failure' });
        } 
    }
});

// this post request will set a new user into the database
app.post('/register', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // fail if blanks
    if (username.trim().length === 0 || email.trim().length === 0 || password.trim().length === 0) {
        res.send(false);
    } else {
        if (await insertnewuser(username, password, email)) {
            res.send({ message: 'Success' });
        } else {
            res.send({ message: 'Failure' });
        } 
    }
});

// this post request will login and return auth token
app.post('/signin', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;

    // fail if blanks
    if (email.trim().length === 0 || password.trim().length === 0) {
        res.send(false);
    } else {
        const thisToken = await signin(email, password);
        if (!thisToken) {
            // this means an error happened
            res.send({ message: 'Failure' })
        } else {
            // this means a token was made
            res.send({ token: thisToken });
        }
    }
});

// this get request will grab captions
app.get('/findusername', async (req, res) => {
    const email = req.query.email;
    const username = await collectusername(email);
    res.send(username);
});

/*
This section is for caption handling.
It will connect with the image handling above.
*/

// this function will query and get all the captions available
async function collectcaptions(imageID) {
    const dbclient = await pool.connect();
    try {
        dbclient.query('BEGIN');
        let captions = [];
        //let query = 'SELECT captiontext, userid, upvotes FROM captions WHERE imageid = $1 AND captionapproval = $2 ORDER BY upvotes DESC';
        const query = 'SELECT c.captiontext, u.username, COALESCE(v.votecount, 0) as votecount FROM captions AS c INNER JOIN users AS u ON u.userid = c.userid INNER JOIN vote_view AS v ON v.captionid = c.captionid WHERE c.imageid = $1 AND c.captionapproval = $2 ORDER BY votecount DESC';
        const result = await dbclient.query(query, [imageID, true]);
        const minimum = Math.min(result.rows.length, 10); // only want 10 captions max
        
        for (let i = 0; i < minimum; i++) {
            captions.push(result.rows[i]);
        }

        return captions;
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// this get request will grab captions
app.get('/collectcaptions', async (req, res) => {
    const imageID = req.query.imageid;
    const captions = await collectcaptions(imageID);
    res.send(captions);
});

// port listen for the end
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

