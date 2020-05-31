import express from 'express';
import mongodb from 'mongodb';
import bodyParser from 'body-parser';
import JWT from 'jsonwebtoken';
import expressJWT from 'express-jwt';
import crypto from 'crypto';
import uuid from 'uuid';
import srp from 'secure-remote-password/server.js';
import sanitize from 'mongo-sanitize'
import expressSanitizer from 'express-sanitizer'
import expressValidator from 'express-validator'
import Payments from './payments.js'

const {check, validationResult} = expressValidator

const MongoClient = mongodb.MongoClient;

//Config
var fallbackSecret = null

if(!process.env.secret){
    console.warn(`Generating JWT secret instead of using from env. Logins won't persist over server restarts.`)
    fallbackSecret = crypto.randomBytes(128).toString('base64')
}

const secret = process.env.secret || fallbackSecret
const STRIPE_KEY = process.env.STRIPE_KEY
const DB_USER = process.env.MONGO_USERNAME || 'ticked'
const DB_PASS = process.env.MONGO_PASSWORD || '1234'
const DB_NAME = process.env.MONGO_DATABASE || 'ticked'
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
app.use(expressSanitizer());
app.use((req, res, next)=>{
    req.body = sanitize(req.body);
    next();
})

//JWT middleware
const JWTmw = expressJWT({
    secret: secret,
});

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

//Setting up DB
var db
async function dbConnect(tries = 0) {
    if(tries > 5){
        throw new Error('MongoClient connection failed, 5 tries exhausted')
    }
    tries++
    try {
        const client = await MongoClient.connect(DB_URL)
        db = await client.db('ticked')
        console.log('Mongo connected')
    } catch (error) {
        console.warn('MongoClient connection failed, trying again in 5 seconds')
        await sleep(5000)
        await dbConnect(tries)
    }
}



//Sample response
app.get('/', (req, res)=>{
    res.send('Ticked-server test response')
})

//Login
// Give salt to client and get client public ephemeral key and username
app.post('/login/salt', [check('username').isString(), check('clientEphemeralPublic')], async (req, res)=>{ 
    const {clientEphemeralPublic, username} = req.body;
    try {
        const vErrors = validationResult(req)
        if(!vErrors.isEmpty()){
            console.log(vErrors)
            throw 'error.login.invalidquery'
        }
        const user = await db.collection("users").findOne({username: username}, {projection: {_id: 0}})
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
        if(typeof error === String){
            res.json({
                err: error,
                success: false
            })
        }else{
            console.log(error)
            res.json({
                err: 'error.login.invalidlogin',
                success: false
            })
        }
    }
})

// Give token and encryptionkey to client and create proof
app.post('/login/token', [check('username').isString(), check('clientEphemeralPublic')], async (req, res)=>{
    try {
        const vErrors = validationResult(req)
        if(!vErrors.isEmpty()){
            console.log(vErrors)
            throw 'error.login.invalidquery'
        }
        const {clientSessionProof, username} = req.body;
        const currentLogin = currentLogins.get(username)
        const serverEphemeralSecret = currentLogin.serverEphemeralSecret
        const clientEphemeralPublic = currentLogin.clientEphemeralPublic
        const salt = currentLogin.salt
        const verifier = currentLogin.verifier
        const userid = currentLogin.userid
        const serverSession = srp.deriveSession(serverEphemeralSecret, clientEphemeralPublic, salt, username, verifier, clientSessionProof)
        const dataEncryptionKey = await getDataKey(userid)
        res.json({
            serverSessionProof: serverSession.proof,
            success: true,
            token: JWT.sign({ username, userid }, secret, { expiresIn: 129600 }),
            key: dataEncryptionKey
        })
    } catch (error) {
        if(typeof error === String){
            res.json({
                err: error,
                success: false
            })
        }else{
            console.log(error)
            res.json({
                err: 'error.servererror',
                success: false
            })
        }
    }
})

//Register
app.post('/register', [check("username").isString(), check("salt"), check("verifier"), check("key§")], async(req, res)=>{
    const vErrors = validationResult(req)
    if(!vErrors.isEmpty()){
        console.log(vErrors)
        throw 'error.register.invalidquery'
    }
    const {username, salt, verifier, key} = req.body;
    try{
        const token = await register(username, salt, verifier, key)
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

app.post('/datakey/set', [check('key')], async(req, res)=>{
    const vErrors = validationResult(req)
    if(!vErrors.isEmpty()){
        console.log(vErrors)
        throw 'error.datakey.invalidquery'
    }
    const {key} = req.body;
    const userid = req.user.userid
    try{
        const token = await setDataKey(userid, key)
        res.json({
            err: null,
            success: true
        })
    }catch(err){
        res.json({
            err: err,
            success: false
        })
    }
})

app.get('/newSubscription', JWTmw, async(req, res)=>{
    const checkout = await payments.getSubscriptionCheckout(req.user.userid)
    res.json({
        success: true,
        err: null,
        token: checkout
    })
})

app.get('/manageSubscription', JWTmw, async(req, res)=>{
    const billingPortal = await payments.getBillingPortal(req.user.userid)
    res.json({
        success: true,
        err: null,
        token: billingPortal
    })
})

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
    const {name, description, taskid, listid} = req.body;
    try {
        await newTask(req.user.userid, listid, taskid, name, description)
        res.json({
            success: true,
            err: null
        });
    } catch (err) {
        console.log(err)
        res.json({
            success: false,
            err: err
        });
    }
});

app.post('/updateTask', JWTmw, async(req, res)=>{
    try {
        const {taskid, listid, name, description, alarm, done} = req.body
        await updateTask(req.user.userid, listid, taskid, name, description, done)
        res.json({
            success: true
        });
    } catch (err) {
        if(typeof err !== String){
            console.error(err)
            err = 'error.servererror'
        }
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
        const customer = await payments.createCustomer()
        await db.collection('users').updateOne({
            stripeCustomer: customer.id
        })
        console.log('Created stripe userid')
    } catch (error) {
        console.error(error)
        throw 'error.servererror'
    }
}

async function register(username, salt, verifier, key){
    const user = await db.collection("users").findOne({username: username}, {projection: {_id: 0}})
    console.log(user)
    if(!user){//User doesnt exist
        const userid = uuid.v4()
        await db.collection("users").insertOne({
            userid,
            username,
            verifier,
            salt,
            dataEncryptionKey: key
        })
        let token = JWT.sign({ userid: userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
        /*
        initUser({
            userid: userid, 
            username: username
        })*/
        if (isDev) console.log(`User registered ${username}: ${token}`);
        return token
    }else{
        if (process.env.NODE_ENV == 'development') console.log(`User already exists`);
        throw 'error.register.usernameexists'
    }
}

async function getDataKey(userid){
    if(!userid) {
        throw 'error.login.invalidquery'
    }
    try {
        const res = await db.collection('tasks').find({userid}, {projection: {_id: 0}}).toArray()
        const user = res[0]
        return user.dataEncryptionKey
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function setDataKey(userid, newKey){
    if(!userid || !newKey) {
        throw 'error.datakey.invalidquery'
    }
    try {
        await db.collection('tasks').updateOne({userid}, {
            $set: {key: newKey}
        })
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function getTasks(userid, listid){
    if(!userid) {
        throw 'error.getTasks.invalidquery'
    }
    try {
        if(listid){
            const res = await db.collection('tasks').find({listid, userid}, {projection: {_id: 0}}).toArray()
            // const res = await pool.query(sql`SELECT * FROM tasks WHERE userid=${userid} AND listid=${listid};`);
            return res;
        }else{
            const res = await db.collection('tasks').find({userid}, {projection: {_id: 0}})
            const tasks = await res.toArray()
            return tasks;
        }
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function getLists(userid){
    if(!userid) throw 'error.getLists.invalidquery'
    try {
        const res = await db.collection('lists').find({userid}, {projection: {_id: 0}}).toArray()
        return res;
    } catch (error) {
        console.error(error);
        throw 'error.servererror'
    }
}

async function newList(list){
    if(list.listid && list.userid && list.name){
        try {
            await db.collection('lists').insertOne({userid: list.userid, name: list.name, listid: list.listid})
        } catch (error) {
            console.error(error)
            throw 'error.servererror'
        }
    }else{
        throw 'error.newlist.invalidquery';
    }
}

async function newTask(userid=null, listid=null, taskid=null, name=null, description=null){
    if(taskid && userid && listid && name){
        try {
            await db.collection('tasks').insertOne({userid, listid, taskid, name, description})
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
            await db.collection('tasks').delete({userid, taskid})
        } catch (error) {
            throw 'error.servererror';
        }
    }else{
        throw 'error.deletetask.invalidquery'
    }
}

async function updateTask(userid=null, listid=null, taskid=null, name=null, description=null, done=false){
    if(taskid && userid && listid){
        try {
            const newTask = {userid, listid, taskid, name, description, done}
            await db.collection('tasks').replaceOne({userid, taskid}, newTask)
        } catch (error) {
            console.error(error)
            throw 'error.servererror'
        }
    }else{
        throw 'error.updatetask.invalidquery';
    }
}

async function removeTask(){

}

async function deleteAccount(userid){
    try {
        if(!userid) throw 'error.deleteAccount.invalidquery'
        try {
            await Promise.all([
                db.collection('tasks').delete({userid}),
                db.collection('lists').delete({userid}),
                db.collection('users').delete({userid})
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

async function initialize () {
    try {
        await dbConnect()
        await app.listen(PORT)
        console.log(`Listening on ${PORT}`)
    } catch (error) {
        console.error(error)
    }
}

initialize()