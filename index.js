import express from 'express';
import NodeCache from 'node-cache';
import slonikQCache from 'slonik-interceptor-query-cache';
import Slonik from 'slonik';
const sql = Slonik.sql;
import bodyParser from 'body-parser';
import JWT from 'jsonwebtoken';
import expressJWT from 'express-jwt';
import crypto from 'crypto';
import argon2 from 'argon2';
import uuid from 'uuid';

//Config
const secret = process.env.secret || crypto.randomBytes(128).toString('base64'); //get secret from env or generate new, possibly dangerous, but better than using pre-defined secret
const DB_URL = process.env.DATABASE_URL+'?ssl=1&rejectUnauthorized=true';
const PORT = process.env.PORT || 5000;

//Setting up express
const app = express();

//Middleware

//Headers
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization');
    next();
});


//Bodyparser
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//JWT middleware
const JWTmw = expressJWT({
    secret: secret,
});

//Setting up DB
const cache = new NodeCache({
    checkperiod: 60,
    stdTTL: 600, //10 minutes
    useClones: false,
});
  
const hashQuery = (query) => {
    return JSON.stringify(query);
};

//Create cacheinterceptor
const interceptors = [
    slonikQCache.createQueryCacheInterceptor({
        storage: {
        get: (query) => {
          return cache.get(hashQuery(query)) || null;
        },
        set: (query, cacheAttributes, queryResult) => {
          cache.set(hashQuery(query), queryResult, cacheAttributes.ttl);
        },
      },
    }),
];

const pool = Slonik.createPool(DB_URL, {
    interceptors: interceptors,
    maximumPoolSize: 10,
    idleTimeout: 30000,
    connectionTimeout: 15000,
});


//Login
app.post('/login', async(req, res)=>{
    const {username, password} = req.body;
    try{
        const pgReturn = await pool.maybeOne(sql`SELECT password, userid FROM users WHERE username = ${username}`); //Get password hash and userid by username
        if(pgReturn){
            if(await argon2.verify(pgReturn.password, password)){//Check password
                let token = JWT.sign({ userid: pgReturn.userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
                res.status(200).json({
                    success: true,
                    err: null,
                    token: token,
                });
            }else{//Invalid password
                res.status(401).json({
                    success: false,
                    token: null,
                    err: 'Username or password is incorrect'
                });
            }
        }else{//Invalid query (incorrect userid)
            res.status(401).json({
                success: false,
                token: null,
                err: 'Username or password is incorrect'
            });
        }
    }
    catch(err){//Something broke
        console.error(err);
    }
});

//Register
app.post('/register', async(req, res)=>{
    const {username, password} = req.body;
    console.log(req.body);
    const userid = uuid.v4();
    try{
        const hashedPassword = await argon2.hash(password);
        const pgReturn = await pool.maybeOne(sql`SELECT userid FROM users WHERE username = ${username}`); //Check if user exists
        console.log(pgReturn);
        if(!pgReturn){//User doesnt exist
            await pool.query(sql`INSERT INTO users (userid, password, username) VALUES (${userid}, ${hashedPassword}, ${username})`); //Insert
            let token = JWT.sign({ userid: userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
            res.json({
                success: true,
                err: null,
                token: token,
            });
            if (process.env.NODE_ENV == 'development') console.log(`User registered ${username}: ${token}`);
        }else{
            if (process.env.NODE_ENV == 'development') console.log(`User already exists`);
            res.status(401).json({
                success: false,
                token: null,
                err: 'User already exists'
            });
        }
    }
    catch(err){//Something broke
        console.error(err);
    }
});


//Proper API
app.get('/getTask/single', async(req, res)=>{
    await pool.maybeOne(); //Query task
});

app.get('/getTask/all', async(req, res)=>{
    var taskIDs = await getTaskIDs();
    var tasks = [];
    await Promise.all(taskIDs.map(async (taskID) => {
        const task = await getTask(taskID);
        tasks.push(task);
    }));
    res.json(tasks);
});

app.get('/newTask', async(req, res)=>{

});

app.get('/updateTask', async(req, res)=>{

});

app.get('/removeTask', async(req, res)=>{

});

async function getTaskIDs(userID){

}

async function getTask(taskID){

}

async function newTask(){

}

async function updateTask(){

}

async function removeTask(){

}

//Error middleware
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') { // Invalid password, lets not log
        res.status(401).send(err);
    }
    else {
        next(err);
    }
});

app.listen(PORT, ()=>{
    console.log(`listening on ${PORT}`);
});