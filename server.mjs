import express from 'express'; // for transactions
import pg from 'pg'; // for pg connection
//import cors from 'cors'; // access control optiona
import bcrypt from 'bcryptjs'; // for handling user passwords
import jwt from 'jsonwebtoken'; // for handling JWT for authorization

/*
This section is for pg connection handling.
This code will instantiate the connection to pg server.
*/

const app = express();
const port = process.env.DB_PORT;
const { Pool } = pg;

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT,
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
app.options('*', function (req,res) { res.sendStatus(200); }); // for cors options issues

/*
This section is for password encryption handling.
User passwords will be encrypted in the DB.
*/

// this async function will provide an encryption
async function encryptPassword(password) {
  const salt = await bcrypt.genSalt(10); // Defines time needed to calculate a single bcrypt hash              
  try {                                  // The higher #, the more hashing rounds are done
    const hashedPassword = await bcrypt.hash(password, salt);
    return hashedPassword;
  } catch (error) {
    console.error('Error encrypting password:', error);
    throw error;
  }
}

// this async function will compare hash passwords
async function comparePassword(password, hashedPassword) {
    try {
      const isMatch = await bcrypt.compare(password, hashedPassword);
      return isMatch;
    } catch (error) {
          console.error('Error comparing passwords:', error);
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

// below creates the JWT
// and houses payload (returned data)
function createToken(userDB) {
    const token = jwt.sign({
        username: userDB // put username from DB here
    }, process.env.SECRETKEY, { expiresIn: '1h' });

    return token;
}

// below code verifies the JWT
// should be used in upvotes and caption uploads
/*
jwt.verify(token, process.env.SECRETKEY, (err, decoded) => {
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
    }, process.env.SECRETKEY, { expiresIn: '1h' });

    res.send(token);
});

// this get request will test JWT provided

app.get('/jwt/clean', async (req, res) => {
    
    const encToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IktpbmdKb2UiLCJpYXQiOjE3NDIyNTI3MzYsImV4cCI6MTc0MjI1NjMzNn0.c8RGR6BGcf5-kCn_DVqp62QjGdRer5WkNZi6n3xeRXc';
   
    jwt.verify(encToken, process.env.SECRETKEY, (err, decoded) => {
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
        throw e;
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
        
        if (result.rows.length === 0) {
            // this means that an incorrect email address was entered
            return false;
        }
        
        // check hash password against hashed user pw for correct email
        const isPasswordCorrect = await comparePassword(password, result.rows[0].password);
        
        if (isPasswordCorrect) {
            // update lastlogin time
            // const timestamp = now.toISOString().slice(0, 19).replace('T', ' ');
            // query = 'UPDATE users SET lastlogin = $1 WHERE email = $2';
            // await dbclient.query(query, [timestamp, email]);
            // await dbclient.query('COMMIT'); added

            // now create usertoken
            query = 'SELECT username FROM users WHERE email = $1';
            result = await dbclient.query(query, [email]);
            const token = createToken(result.rows[0].username);
            return token;
        } else {
            return isPasswordCorrect;
        }

    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

/*
// function to collect a username (not in use)
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
*/

// this get request will check if a user exists
app.post('/checkifexists', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;

    // fail if blanks
    if (username.trim().length === 0 || email.trim().length === 0) {
        res.send({ message: 'Failure' });
    } else {
        if (await checkifexists(username, email)) {
            res.send({ message: 'Success' });
        } else {
            res.send({ message: 'Failure' });
        } 
    }
});

// this post request will register a new user into the database
app.post('/register', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;

    // fail if blanks
    if (username.trim().length === 0 || email.trim().length === 0 || password.trim().length === 0) {
        res.send({ message: 'Failure' });
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
        res.send({ message: 'Failure' });
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

/*
// this get request will grab a username given an email (not in use)
app.get('/findusername', async (req, res) => {
    const email = req.query.email;
    const username = await collectusername(email);
    res.send(username);
});
*/

/*
This section is for caption handling.
Users will be able to:
1) upload a new caption (auto approved)
2) upvote an existing caption
*/

// this function will query and get all the captions available
async function collectcaptions(imageID) {
    const dbclient = await pool.connect();
    try {
        dbclient.query('BEGIN');
        let captions = [];
        
        const query = 'SELECT c.captiontext, u.username, COALESCE(v.votecount, 0) as votecount FROM captions AS c LEFT JOIN users AS u ON u.userid = c.userid LEFT JOIN vote_view AS v ON v.captionid = c.captionid WHERE c.imageid = $1 AND c.captionapproval = $2 ORDER BY votecount DESC';
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


// this function will assist in upvoting
async function voting(captionText, captionAuthor, authUser, captionType) {
    const dbclient = await pool.connect();
    try {
        dbclient.query('BEGIN');
        
        //check supabase for the query steps
        // first query users table to find the authors userID
        // next query captions table to find captionID for the caption text and author that match
        // finally check if authUser has already upvoted this captionID in voting table
            // if no, then add as new entry
            // if yes, then remove previous entry
        
        let query = 'SELECT userid FROM users WHERE username = $1';
        let result = await dbclient.query(query, [authUser]);
        const authUserID = result.rows[0].userid; // set authUser userid
        
        query = 'SELECT userid FROM users WHERE username = $1';
        result = await dbclient.query(query, [captionAuthor]);
        const captionAuthorID = result.rows[0].userid; // set captionAuthor userid

        query = 'SELECT captionid FROM captions WHERE captiontext = $1 AND userid = $2';
        result = await dbclient.query(query, [captionText, captionAuthorID]);
        const captionTextID = result.rows[0].captionid; // set captionText captionid

        query = 'SELECT voteid FROM voting WHERE captionid = $1 AND userid = $2';
        result = await dbclient.query(query, [captionTextID, authUserID]);

        if (result.rows.length === 0) { 
            // authUser has not voted for this caption yet
            // add their vote to the table
            query = 'INSERT INTO voting (captionid, userid, type) VALUES ($1, $2, $3)';
            await dbclient.query(query, [captionTextID, authUserID, captionType]);
            await dbclient.query('COMMIT');
            return 'added';
        } else {
            // authUser has voted for this caption
            // remove their vote from the table
            query = 'DELETE FROM voting WHERE captionid = $1 AND userid = $2';
            await dbclient.query(query, [captionTextID, authUserID]);
            await dbclient.query('COMMIT');
            return 'removed'
        }
       
    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// this post request will allow an upvote by user
app.post('/votecaption', async (req, res) => {
    const captionText = req.body.captiontext; // grab caption's text
    const captionAuthor = req.body.captionuser; // grab caption's author
    const captionType = req.body.type; // grab type of vote (upvote or downvote)
    const checkToken = req.headers['authorization'] && req.headers['authorization'].split(' ')[1]; // grab token

    // verify that token is an auth user
    jwt.verify(checkToken, process.env.SECRETKEY, async (err, decoded) => {
        
        if (err) {
            // token did not work
            res.send({ message: 'Failure' });
        } else {
            // token did work and username can be grabbed
            const authUser = decoded.username;
            const voted = await voting(captionText, captionAuthor, authUser, captionType);
            if (voted == 'added') {
                res.send({ message: 'Added' });
            } else if (voted == 'removed') {
                res.send({ message: 'Removed' });
            } else {
                res.send({ message: 'Failure' });
            }
        }
    });
});

// this function will assist in upvoting
async function captioning(captionText, imageID, authUser) {
    const dbclient = await pool.connect();
    try {
        dbclient.query('BEGIN');
        
        // check supabase for the query steps
        // first query users table to find userID for authUser
        // finally, insert new caption into captions table
        // userid, imageid, captiontext, captionapproval (default true)
        
        let query = 'SELECT userid FROM users WHERE username = $1';
        const result = await dbclient.query(query, [authUser]);
        const authUserID = result.rows[0].userid; // set authUser userid
        
        query = 'INSERT INTO captions (userid, imageid, captiontext, captionapproval) VALUES ($1, $2, $3, $4)';
        await dbclient.query(query, [authUserID, imageID, captionText, true]);
        await dbclient.query('COMMIT');

        return true;

    } catch (e) {
        await dbclient.query('ROLLBACK');
        throw e;
    } finally {
        dbclient.release();
    }
}

// this post request will allow a user to post a caption
app.post('/addnewcaption', async (req, res) => {
    const captionText = req.body.captiontext; // grab caption's text
    const imageID = req.body.imageid; // grab image id
    const checkToken = req.headers['authorization'] && req.headers['authorization'].split(' ')[1]; // grab token

    // verify that token is an auth user
    jwt.verify(checkToken, process.env.SECRETKEY, async (err, decoded) => {
        
        if (err) {
            // token did not work
            res.send({ message: 'Failure' });
        } else {
            // token did work and username can be grabbed
            const authUser = decoded.username;
            const writeCaption = await captioning(captionText, imageID, authUser);
            if (writeCaption) {
                res.send({ message: 'Success' });
            }
        }
    });
});

// port listen for the end
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});

