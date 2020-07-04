import express from 'express';
import mongodb from 'mongodb';
import bodyParser from 'body-parser';
import JWT from 'jsonwebtoken';
import expressJWT from 'express-jwt';
import crypto from 'crypto';
import {v4 as uuidv4} from 'uuid';
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
const STRIPE_HOOK_SECRET = process.env.STRIPE_HOOK_SECRET
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
    res.setHeader('Access-Control-Allow-Headers', 'Content-type,Authorization')
    if(process.env.NODE_ENV !== "development"){
        res.setHeader('Access-Control-Allow-Origin', 'https://ticked.jusola.xyz')
        res.setHeader('Vary', 'Origin')
    }else{
        res.setHeader('Access-Control-Allow-Origin', '*')
    }

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
    algorithms: ['HS256']
});

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

//Setting up DB
var db
async function dbConnect(tries = 0) {
    tries++
    try {
        console.log("Connecting mongo")
        const client = await MongoClient.connect(DB_URL, { useUnifiedTopology:true })
        db = await client.db(DB_NAME)
        console.log('Mongo connected')
    } catch (error) {
        console.warn(`MongoClient connection failed, trying again in ${Math.min(tries*30, 60*30)} seconds`)
        console.log(error)
        await sleep(Math.min(tries*30*1000, 1000*60*30))
        await dbConnect(tries)
    }
}



// Sample response
app.get('/', (req, res)=>{
    res.send('Ticked-server test response')
})

// Login
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
app.post('/register', [check("username").isString(), check("salt"), check("verifier")], async(req, res)=>{
    const vErrors = validationResult(req)
    if(!vErrors.isEmpty()){
        console.log(vErrors)
        res.json({
            success: false,
            err: 'error.register.invalidquery'
        })
        return
    }
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

app.post('/stripe-hook', bodyParser.raw({type: 'application/json'}), async(req, res) => {
    const sig = req.headers['stripe-signature'];
  
    let event;
  
    try {
      event = await stripe.webhooks.constructEvent(req.body, sig, STRIPE_HOOK_SECRET);
    } catch (err) {
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
    
    if (event.type === 'customer.subscription.updated') {
        try {
            const session = event.data.object
            console.log(session)
            const customer = session.customer
            const status = session.status
            await setCustomerSubscriptionStatus(customer, status)
        } catch (error) {
            res.status(400).send(`Error: ${error.toString()}`)
        }
      }
    // Return a response to acknowledge receipt of the event
    res.json({received: true})
})

app.post('/datakey/set', [check('key')], JWTmw, async(req, res)=>{
    const vErrors = validationResult(req)
    if(!vErrors.isEmpty()){
        console.log(vErrors)
        throw 'error.datakey.invalidquery'
    }
    const {key} = req.body
    const userid = req.user.userid
    try{
        await setDataKey(userid, key)
        res.json({
            err: null,
            success: true
        })
    }catch(err){
        console.warn(error)
        res.json({
            err: err,
            success: false
        })
    }
})

app.get('/newSubscription', JWTmw, async(req, res)=>{
    const customerID = await getCustomerID(req.user.userid)
    const checkout = await payments.getSubscriptionCheckout(req.user.userid, customerID)
    res.json({
        success: true,
        err: null,
        token: checkout
    })
})

app.get('/manageSubscription', JWTmw, async(req, res)=>{
    const customerID = await getCustomerID(req.user.userid)
    const billingPortal = await payments.getBillingPortal(customerID)
    res.json({
        success: true,
        err: null,
        url: billingPortal
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
        await createCustomer(user.userid)
    } catch (error) {
        console.error(error)
        throw 'error.servererror'
    }
}

async function createCustomer(userid){
    try {
        const customerID = await payments.newCustomer(userid)
        await db.collection('users').updateOne({userid}, {
            $set: {stripeID: customerID}
        })
        console.log('Created stripe userid')
        return customerID
    } catch (error) {
        console.error(error)
    }
}

async function register(username, salt, verifier){
    const user = await db.collection("users").findOne({username: username}, {projection: {_id: 0}})
    console.log(user)
    if(!user){//User doesnt exist
        const userid = uuidv4()
        await db.collection("users").insertOne({
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

async function getDataKey(userid){
    if(!userid) {
        throw 'error.login.invalidquery'
    }
    try {
        const user = await db.collection('users').findOne({userid}, {projection: {_id: 0}})
        console.log(user)
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
        await db.collection('users').updateOne({userid}, {
            $set: {dataEncryptionKey: newKey}
        })
    } catch (error) {
        console.error(error)
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

async function getCustomerID (userid){
    try {
        if(userid){
            const user = await db.collection("users").findOne({userid: userid}, {projection: {_id: 0}})
            if(user.stripeID){
                return user.stripeID
            }else{
                return await createCustomer(userid)
            }
        }else{
            throw 'error.getcustomerid'
        }
    } catch (error) {
        throw 'error.getcustomerid'
    }    
}

async function getUserIDByStripe (customerID){
    try {
        if(customerID){
            const user = await db.collection("users").findOne({stripeID: customerID}, {projection: {_id: 0}})
            if(user.userid){
                return user.userid
            }
        }else{
            throw 'error.getcustomerid'
        }
    } catch (error) {
        throw 'error.getcustomerid'
    }    
}

async function setCustomerSubscriptionStatus (customerid, newStatus){
    try {
        const userID = await getUserIDByStripe(customerid)
        await db.collection('users').updateOne({userid}, {
            $set: {subscriptionStatus: newStatus}
        })
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