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
const isDev = true;

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
                res.json({
                    success: true,
                    err: null,
                    token: token,
                });
            }else{//Invalid password
                res.json({
                    success: false,
                    token: null,
                    err: 'Username or password is incorrect'
                });
            }
        }else{//Invalid query (incorrect userid)
            res.json({
                success: false,
                token: null,
                err: 'Username or password is incorrect'
            });
        }
    }
    catch(err){//Something broke
        console.error(err);
        res.json({
            success: false,
            token: null,
            err: 'Internal server error'
        });
    }
});

//Register
app.post('/register', async(req, res)=>{
    const {username, password} = req.body;
    const userid = uuid.v4();
    try{
        const hashedPassword = await argon2.hash(password);
        const pgReturn = await pool.maybeOne(sql`SELECT userid FROM users WHERE username = ${username}`); //Check if user exists
        if(!pgReturn){//User doesnt exist
            await pool.query(sql`INSERT INTO users (userid, password, username) VALUES (${userid}, ${hashedPassword}, ${username})`); //Insert
            let token = JWT.sign({ userid: userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
            res.json({
                success: true,
                err: null,
                token: token,
            });
            if (isDev) console.log(`User registered ${username}: ${token}`);
        }else{
            if (process.env.NODE_ENV == 'development') console.log(`User already exists`);
            res.json({
                success: false,
                token: null,
                err: 'User already exists'
            });
        }
    }
    catch(err){//Something broke
        console.error(err);
        res.json({
            success: false,
            token: null,
            err: 'Internal server error'
        });
    }
});


//Proper API
app.get('/getTask/single', JWTmw, async(req, res)=>{
    await pool.maybeOne(); //Query task
});

app.get('/getTask/all', JWTmw, async(req, res)=>{
    try {
        const tasks = await getTasks(req.user.userid);
        res.json({
            success: true,
            tasks: tasks
        })
    } catch (error) {
        res.json({
            success: false
        })
    }
});

app.post('/newTask', JWTmw, async(req, res)=>{
    var {name, description} = req.body;
    const taskid = uuid.v4();
    try {
        if(!name) name = null
        if(!description) description = null
        const pgRes = await pool.query(sql`INSERT INTO tasks (userid, taskid, name, description) VALUES (${req.user.userid}, ${taskid}, ${name}, ${description})`);
        res.json({
            success: true
        });
    } catch (error) {
        res.json({
            success: false,
            error: "Internal server error"
        });
        console.error(error);
    }
    
});

app.post('/updateTask', JWTmw, async(req, res)=>{
    try {
        await updateTask(req.body);
        res.json({
            success: true,
        });
    } catch (error) {
        res.json({
            success: false,
            error: error
        });
    }
    
});

app.post('/removeTask', JWTmw, async(req, res)=>{

});

async function getTasks(userID){
    try {
        const res = await pool.query(sql`SELECT * FROM tasks WHERE userid=${userID};`);
        return res.rows;
    } catch (error) {
        throw new Error('Internal server error');
    }
}

async function getTask(taskID){
    //Not implemented, for debug
    return {
        name: taskID,
        taskid: taskID,
        description: "A nice task that should overflow. Here's a lot of stuff to fill space: Lorem ipsum dolor sit amet, phasellus vestibulum enim, volutpat elit elit. Mi curabitur, magna parturient euismod, pede adipiscing arcu. Tincidunt in pulvinar, ut natoque, erat volutpat dolor. In gravida, vehicula fermentum blandit, consectetuer arcu. Sit quia, tincidunt quis gravida. Placerat dui arcu, vestibulum interdum, convallis tincidunt. Lectus deserunt felis, duis ante felis. In nunc curabitur, dui nec vulputate. Tristique ut suspendisse, et justo, fringilla semper sem. Sed sem in. Metus varius, cursus sollicitudin, aliquet nulla hac. Volutpat eros, mi parturient, lectus vestibulum metus."
    }
}

async function newTask(){

}

async function updateTask(newTask){
    if(newTask.taskid){
        try {
            if(!newTask.name) newTask.name = null
            if(!newTask.description) newTask.description = null
            if(newTask.description === -1 && newTask.name !== -1){//modify name
                await pool.query(sql`UPDATE tasks SET name = ${newTask.name} WHERE taskid=${newTask.taskid};`);
            }else if(newTask.name === -1 && newTask.description !== -1){//modify desc
                await pool.query(sql`UPDATE tasks SET description = ${newTask.description} WHERE taskid=${newTask.taskid};`);
            }else if(newTask.name !== -1 && newTask.description !== -1){ //modify all
                await pool.query(sql`UPDATE tasks SET name = ${newTask.name}, description = ${newTask.description} WHERE taskid=${newTask.taskid};`);
            }else{
                throw new Error('Nothing to modify');
            }
        } catch (error) {
            console.error(error);
            throw error;
        }

    }else{
        throw new Error('No task id');
    }
}

async function removeTask(){

}

//Error middleware
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') { // Invalid token, lets log as invalidToken
        console.warn('Invalid token', err);
        res.status(401).send(err);
    }
    else {
        next(err);
    }
});

app.listen(PORT, ()=>{
    console.log(`listening on ${PORT}`);
});