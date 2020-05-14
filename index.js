import express from 'express';
import mongodb from 'mongodb';
import bodyParser from 'body-parser';
import JWT from 'jsonwebtoken';
import expressJWT from 'express-jwt';
import crypto from 'crypto';
import argon2 from 'argon2';
import uuid from 'uuid';
import srp from 'secure-remote-password/server.js';
import sanitize from 'mongo-sanitize'
import Payments from './payments.js'

const MongoClient = mongodb.MongoClient;

//Config
var fallbackSecret = null

if(!process.env.secret){
    console.warn(`Generating JWT secret instead of using from env. Logins won't persist over server restarts.`)
    fallbackSecret = crypto.randomBytes(128).toString('base64')
}

console.log(process.env)

const secret = process.env.secret || fallbackSecret
const STRIPE_KEY = process.env.STRIPE_KEY
const DB_USER = process.env.MONGO_USERNAME || 'ticked'
const DB_PASS = process.env.MONGO_PASSWORD || '1234'
const DB_NAME = process.env.MONGO_DATABASE || 'postgres'
const DB_HOST = process.env.MONGO_SERVICE_HOST || 'localhost'
const DB_PORT = process.env.MONGO_SERVICE_PORT || 27017
const DB_URL = process.env.DATABASE_URL || `mongodb://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;
const PORT = process.env.PORT || 5000;
const isDev = true;

const payments = new Payments(STRIPE_KEY)

var currentLogins = new Map()

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
app.use((req, res, next)=>{
    req.body = sanitize(req.body);
    next();
})

//JWT middleware
const JWTmw = expressJWT({
    secret: secret,
});

//Setting up DB
var db
MongoClient.connect(DB_URL).then((returnDB)=>{
    db=returnDB
}).catch((err)=>{
    console.error(err)
})

//Sample response
app.get('/', (req, res)=>{
    res.send('Ticked-server test response')
})

//Login
// Give salt to client and get client public ephemeral key and username
app.post('/login/salt', async (req, res)=>{ 
    const {clientEphemeralPublic, username} = req.body;
    try {
        const user = await db.collection("users").findOne({username: username})
        console.log(user)
        if(user){
            const { verifier, salt, userid } = user
            const serverEphemeral = await srp.generateEphemeral(verifier)
            currentLogins.set(username, {clientEphemeralPublic, serverEphemeralSecret: serverEphemeral.secret, salt, verifier, userid})
            res.json({
                success: true,
                salt,
                serverEphemeralPublic: serverEphemeral.public
            })
        }else{
            // return some random salt here ... not yet implemented
            res.json({
                success: true,
                salt: '1234',
                serverEphemeralPublic: '1234'
            })
        }
    } catch (error) {
        console.log(error)
        res.json({
            err: 'error.servererror',
            success: false
        })
    }
})

// Give token to client and create proof
app.post('/login/token', async (req, res)=>{
    try {
        const {clientSessionProof, username} = req.body;
        const currentLogin = currentLogins.get(username)
        const serverEphemeralSecret = currentLogin.serverEphemeralSecret
        const clientEphemeralPublic = currentLogin.clientEphemeralPublic
        const salt = currentLogin.salt
        const verifier = currentLogin.verifier
        const userid = currentLogin.userid
        console.log({serverEphemeralSecret, clientEphemeralPublic, salt, username, verifier, clientSessionProof})
        const serverSession = srp.deriveSession(serverEphemeralSecret, clientEphemeralPublic, salt, username, verifier, clientSessionProof)
        res.json({
            serverSessionProof: serverSession.proof,
            success: true,
            token: JWT.sign({ username, userid }, secret, { expiresIn: 129600 })
        })
    } catch (error) {
        console.warn(error)
        res.json({
            err: 'error.login.invalidlogin',
            success: false
        })
    }
})

app.post('/login', async(req, res)=>{
    const {username, password} = req.body;
    if(!username || !password){
        res.json({
            success: false,
            token: null,
            err: 'error.login.invalidquery'
        });
    }                 
    try{
        const pgReturn = await pool.maybeOne(sql`
        -- @cache-ttl 600
        SELECT 
            password, 
            userid
        FROM 
            users 
        WHERE 
            username = ${username}`
        );
        console.log(pgReturn)
        console.log(username)
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
                    err: 'error.login.invalidlogin'
                });
            }
        }else{
            res.json({
                success: false,
                token: null,
                err: 'error.login.invalidlogin'
            });
        }
    }catch(err){//Something broke
        console.log("Internal error")
        console.error(err);
        res.json({
            success: false,
            token: null,
            err: 'error.servererror'
        });
    }
});

//Register
app.post('/register', async(req, res)=>{
    const {username, salt, verifier} = req.body;
    try{
        const token = await register(username, salt, verifier)
        res.json({
            token: token,
            err: null,
            success: true
        })
    }
    catch(err){//Something broke
        if(typeof err === String){
            res.json({
                success: false,
                token: null,
                err: err
            });
        }else{
            console.error(err);
            res.json({
                success: false,
                token: null,
                err: 'error.servererror'
            });
        }
    }
});

app.post('/getLists', JWTmw, async(req, res)=>{
    try {
        const lists = await getLists(req.user.userid);
        res.json({
            success: true,
            lists: lists,
            err: null
        });
    } catch (error) {
        console.error(error)
        res.json({
            success: false,
            err: error
        });
    }
});

app.post('/newList', JWTmw, async(req, res)=>{
    var {name, listid} = req.body;
    try {
        await newList({
            name: name,
            listid: listid,
            userid: req.user.userid
        })
        res.json({
            success: true
        });
    } catch (err) {
        res.json({
            success: false,
            err: err
        });
    }
})

app.post('/getTask/single', JWTmw, async(req, res)=>{
    await pool.maybeOne(); //Query task
});

app.post('/getTask/all', JWTmw, async(req, res)=>{
    try {
        const tasks = await getTasks(req.user.userid, req.body.listid);
        res.json({
            success: true,
            tasks: tasks
        })
    } catch (error) {
        res.json({
            success: false,
            err: error
        })
    }
});

app.post('/newTask', JWTmw, async(req, res)=>{
    var {name, description, taskid, listid} = req.body;
    try {
        await newTask({
            name: name,
            description: description,
            taskid: taskid,
            listid: listid,
            userid: req.user.userid
        })
        res.json({
            success: true
        });
    } catch (err) {
        res.json({
            success: false,
            err: err
        });
    }
});

app.post('/updateTask', JWTmw, async(req, res)=>{
    try {
        await updateTask(req.body);
        res.json({
            success: true,
        });
    } catch (err) {
        res.json({
            success: false,
            err: err
        });
    }
});

app.post('/deleteTask', JWTmw, async(req, res)=>{
    try{
        await deleteTask(req.body.taskid);
        res.json({
            success: true
        })
    }catch(err){
        res.json({
            success: false,
            err: err
        })
    }
});

app.post('/deleteAccount', JWTmw, async(req, res)=>{
    try{
        await deleteAccount(req.user.userid);
        res.json({
            success: true
        })
    }catch(err){
        res.json({
            success: false,
            err: err
        })
    }
});

async function initUser(user) {
    if(!user.username || !user.userid) throw 'error.invalidquery'
    try {
        console.log(`Initing ${user.username}`)
    } catch (error) {
        console.error(error)
        throw 'error.servererror'
    }
}

async function register(username, salt, verifier){
    const user = await db.collection("users").findOne({username: username})
    console.log(user)
    if(!user){//User doesnt exist
        const userid = uuid.v4()
        await db.collection("users").insert({
            userid,
            username,
            verifier,
            salt
        })
        let token = JWT.sign({ userid: userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
        initUser({
            userid: userid, 
            username: username
        })
        if (isDev) console.log(`User registered ${username}: ${token}`);
        return token
    }else{
        if (process.env.NODE_ENV == 'development') console.log(`User already exists`);
        throw 'error.register.usernameexists'
    }
}

async function getTasks(userID, listid){
    if(!userID) {
        throw 'error.getTasks.invalidquery'
    }
    try {
        if(listid){
            const res = await pool.query(sql`SELECT * FROM tasks WHERE userid=${userID} AND listid=${listid};`);
            return res.rows;
        }else{
            const res = await pool.query(sql`SELECT * FROM tasks WHERE userid=${userID};`);
            return res.rows;
        }
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function getLists(userID){
    if(!userID) throw 'error.getLists.invalidquery'
    try {
        const res = await pool.query(sql`SELECT * FROM lists WHERE userid=${userID};`);
        return res.rows;
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function newList(list){
    if(list.listid && list.userid && list.name){
        try {
            await pool.query(sql`INSERT INTO lists (userid, name, listid) VALUES (${list.userid}, ${list.name}, ${list.listid})`);
        } catch (error) {
            console.error(error)
            throw 'error.servererror'
        }
    }else{
        throw 'error.newlist.invalidquery';
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

async function newTask(task){
    if(task.description === undefined) task.description = null
    if(task.taskid && task.userid && task.userid && task.listid){
        try {
            await pool.query(sql`INSERT INTO tasks (userid, taskid, name, description, listid) VALUES (${task.userid}, ${task.taskid}, ${task.name}, ${task.description}, ${task.listid})`);
        } catch (error) {
            console.error(error)
            throw 'error.servererror'
        }
    }else{
        throw 'error.newtask.invalidquery';
    }
}

async function deleteTask(taskid, userid){
    if(taskid){
        try {
            await pool.query(sql`DELETE FROM tasks WHERE taskid=${taskid}`);
        } catch (error) {
            throw 'error.servererror';
        }
    }else{
        throw 'error.deletetask.invalidquery'
    }
}

async function updateTask(newTask){
    if(newTask.taskid){
        try {
            var queries = [];
            if(newTask.name !== undefined){
                queries.push(sql`name = ${newTask.name}`);
            }
            if(newTask.description !== undefined){
                queries.push(sql`description = ${newTask.description}`);
            }
            if(newTask.alarm !== undefined){
                if(newTask.alarm === null){
                    queries.push(sql`alarm = NULL`);
                }else{
                    queries.push(sql`alarm = ${newTask.alarm}`);
                }
            }
            if(queries.length < 1){
                throw 'error.updatetask.nochanges';
            }
            await pool.query(sql`UPDATE tasks SET ${sql.join(queries, sql`, `)} WHERE taskid=${newTask.taskid};`);
        } catch (error) {
            console.error(error);
            throw 'error.servererror'
        }
    }else{
        throw 'error.updatetask.invalidquery'
    }
}

async function removeTask(){

}

async function deleteAccount(userID){
    try {
        if(!userID) throw 'error.deleteAccount.invalidquery'
        try {
            await Promise.all([
                pool.query(sql`
                DELETE FROM
                    users
                WHERE
                    userid = ${userID};
                `),
                pool.query(sql`
                DELETE FROM
                    tasks
                WHERE
                    userid = ${userID};
                `),
                pool.query(sql`
                DELETE FROM
                    lists
                WHERE
                    userid = ${userID};
                `)
            ]);
        } catch (error) {
            console.error(error)
            throw 'error.servererror'
        }
    } catch (error) {
        throw error.toString()
    }

}

async function setKey(userid, newKey){
    try {
        if(newKey){
            await pool.query(sql`
            UPDATE
                users
            SET
                key = ${newKey}
            WHERE
                userid = ${userid}
            `)
        }else{
            await pool.query(sql`
            UPDATE
                users
            SET
                key = NULL
            WHERE
                userid = ${userid}
            `)
        }
        return true
    } catch (error) {
        console.error(error)
        throw error
    }
}

async function getKey(userid){
    try {
        const res = await pool.query(sql`
            SELECT
                key
            FROM
                users
            WHERE
                userid = ${userid}
        `)
        console.log(res.rows[0])
        return res.rows[0]
    } catch (error) {
        console.error(error)
        throw error
    }
}

//Error middleware
app.use(function (err, req, res, next) {
    if (err.name === 'UnauthorizedError') { // Invalid token, lets log as
        console.warn('Invalid token', err);
        res.send({
            success: false,
            err: 'error.invalidtoken'
        })
    }
    else {
        next(err);
    }
});

app.listen(PORT, ()=>{
    console.log(`listening on ${PORT}`);
});