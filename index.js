/*jshint esversion: 6 */

// Configuration
require('dotenv').config();
const mode = process.env.MODE; //(Choose: pro/dev) pro - producation or dev - development
const PORT = process.env.PORT || 3001;
const connectSocket = "http://localhost:3000";
const whitelist = mode === "dev"?['http://localhost:3000','http://localhost:3001']:['https://okki.kz','https://okki.vercel.app'];
//

// Library 
const compression = require('compression');
const express = require('express');
const app = express();
const http = require('http');
const {Server} = require("socket.io");
const server = http.createServer(app);
const cors = require('cors');
const helmet = require('helmet');
//

const shouldCompress = (req, res) => {
    if (req.headers['x-no-compression']) {
     return false;
    }
    return compression.filter(req, res);
};
const exceptions = ['.js', '.css', '.ico', '.jpg', '.jpeg', '.png', '.gif', '.tiff', '.tif', '.bmp', '.svg', '.ttf', '.eot', '.woff', '.php', '.xml', '.xsl','.json'];
const setCache = function (req, res, next) {
  const period = 1 * 24 * 60 * 60 * 1000;
  if(!exceptions.some(v => req.url.includes(v))){
    res.contentType('application/json;charset=utf-8');
  }
  if (req.method == 'GET') {
    res.set('Cache-control', `public, max-age=${period}`);
  } else {
    res.set('Cache-control', `no-store`);
  }
  next();
}
app.use(compression({ filter: shouldCompress, threshold: 0 }));
app.use(setCache)
const corsOptions = {
    origin: whitelist,
    allowedHeaders: 'Content-Type, Authorization,WWW-Authenticate,Accept,Origin',
    methods: "GET,POST,DELETE",
    optionsSuccessStatus: 200,
    credentials:true
};
app.set('trust proxy', true);
app.use(express.static('public')); 
app.use('/images', express.static('images'));
app.use(cors(corsOptions));
app.use(helmet());
app.disable('x-powered-by');
app.use((req, res, next) => {
    const www = req.headers['www-authenticate'];
    const originStatus = req.get('origin');
    const modeStatus = mode === "dev"?"http":"https";
    const httpStatus = req.protocol;
    if(originStatus!==undefined) {
        if (!www&&httpStatus===modeStatus&&originStatus.includes(whitelist)) {
            return res.sendStatus(403);
        }
        else {
            if(www===process.env.authHeader) {
                next();
            } else {
                console.log('\x1b[31m%s\x1b[0m',"Someone tried to fetch backend");
                return res.sendStatus(401);
            }
        }
    } else {
        res.sendStatus(403);
    }
});
app.use(express.json());
app.use(express.urlencoded({extended:true}));



// Router start
const authLogin = require('./pages/user/login');
app.use(authLogin);
const database = require('./pages/user/index');
app.use(database);

// Router finish

app.route('/').get((req, res) => {
    // const s = require("./pages/user/index.js")
    res.send(`<h1>Welcome to Okki Api Server</h1>`);
});
app.route('/ws').get((req, res) => {
    res.send(`<h1>Welcome to Okki WebSocket</h1>`);
});

const io = new Server(server,{
    cors: {
        origin: connectSocket,
        methods: ["GET", "POST"],
        transports: ['websocket', 'polling'],
        credentials: true
    },
    allowEIO3: true
});


io.of("/ws").on('connection',socket=>{
    const rooms = socket.handshake.query.c;
    if(rooms!==undefined){
        socket.join(rooms);
        socket.on("connectToRoom",(e)=>{
            console.log("Room name is "+e.text);
            socket.broadcast.to(rooms).emit("get_data",e);
        });
        socket.on("send_qustion",e=>{
            socket.broadcast.to(rooms).emit("get_question",e);
        });
    }
});

app.use((req, res,next) => {
    return res.sendStatus(404);
});

app.use((err, req, res,next) => {
    console.log('\x1b[31m%s\x1b[0m',"[500 Error] New error on backend");
    console.log(err);
    return res.sendStatus(500);
});

app.listen(PORT,()=>{
    console.log('\x1b[33m%s\x1b[0m',"Server is running on port "+PORT);
});