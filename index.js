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

import Payments from './payments.js'

//Config
var fallbackSecret = null

if(!process.env.secret){
    console.warn(`Generating JWT secret instead of using from env. Logins won't persist over server restarts.`)
    fallbackSecret = crypto.randomBytes(128).toString('base64')
}

const secret = process.env.secret || fallbackSecret
const STRIPE_KEY = process.env.STRIPE_KEY
const DB_USER = process.env.POSTGRES_USER || 'postgres'
const DB_PASS = process.env.POSTGRES_PASSWORD || 'postgres'
const DB_NAME = process.env.POSTGRES_DB || 'postgres'
const DB_HOST = process.env.POSTGRES_SERVICE_HOST || 'localhost'
const DB_PORT = process.env.POSTGRES_SERVICE_PORT || 5432
const DB_URL = process.env.DATABASE_URL || `postgres://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}`;
const PORT = process.env.PORT || 5000;
const isDev = true;
const allowedDBrows = ['alarm', 'description', 'name', 'listid'];

const payments = new Payments(STRIPE_KEY)

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
    stdTTL: 3600, //1 hour
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

//Sample response
app.get('/', (req, res)=>{
    res.send('Ticked-server test response')
})

//Login
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
    const {username, password} = req.body;
    const userid = uuid.v4();
    try{
        const hashedPassword = await argon2.hash(password);
        const pgReturn = await pool.maybeOne(sql`
            -- @cache-ttl 600
            SELECT
                userid
            FROM 
                users 
            WHERE 
                username = ${username}`
        ); //Check if user exists
        if(!pgReturn){//User doesnt exist
            await pool.query(sql`
                -- @cache-ttl 600
                    INSERT INTO 
                    users (userid, password, username) 
                VALUES (${userid}, ${hashedPassword}, ${username})
            `); //Insert
            let token = JWT.sign({ userid: userid, username: username }, secret, { expiresIn: 129600 }); // Sign JWT token
            res.json({
                success: true,
                err: null,
                token: token,
            });
            await initUser({
                userid: userid, 
                username: username
            })
            if (isDev) console.log(`User registered ${username}: ${token}`);
        }else{
            if (process.env.NODE_ENV == 'development') console.log(`User already exists`);
            res.json({
                success: false,
                token: null,
                err: 'error.register.usernameexists'
            });
        }
    }
    catch(err){//Something broke
        console.error(err);
        res.json({
            success: false,
            token: null,
            err: 'error.servererror'
        });
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
    } catch (error) {
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