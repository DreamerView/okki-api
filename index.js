// Configuration
require('dotenv').config()
const mode = process.env.MODE; //(Choose: pro/dev) pro - producation or dev - development
const PORT = process.env.PORT || 3001;
const connectSocket = "http://localhost:3000";
const IpHostList = mode === "dev"?['localhost']:['okki.kz','zhenil-next.vercel.app'];
//

// Library 
const express = require('express');
const app = express();
const http = require('http');
const {Server} = require("socket.io");
const server = http.createServer(app);
const cors = require('cors');
const modeRes1 = mode==="dev"?"localhost":"zhenil-next.vercel.app"
const modeRes2 = mode==="dev"?"localhost":"okki.kz"
const helmet = require('helmet');
const {v4: uuidv4} = require('uuid');
console.log(uuidv4());
//


// const generatePassword = () => {
//     var length = 64,
//         charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
//         retVal = "";
//     for (var i = 0, n = charset.length; i < length; ++i) {
//         retVal += charset.charAt(Math.floor(Math.random() * n));
//     }
//     return retVal;
// };

// console.log(generatePassword());

var corsOptions = {
    // origin: connectSocket,
    allowedHeaders: 'Content-Type,Authorization,Accept',
    methods: "GET,POST",
    optionsSuccessStatus: 200,
    credentials:true
}
// app.use((req, res, next) => {
//     let validHost = IpHostList; // Put your IP whitelist in this array
    
//     if(validHost.includes(req.hostname)){
//         console.log("Host ok");
//         next();
//     } else{
//         console.log("Bad host: " + req.hostname);
//         // const err = new Error("Bad host: " + req.connection.remoteAddress);
//         // next(err);
//         res.status(401).send("<h1>Access denied!</h1><p>Please exit this page!</p>")
//     }
// })
app.use(express.json())
app.use(express.urlencoded({extended:true}))

app.use(cors(corsOptions));
app.use(helmet());
app.disable('x-powered-by');

// Router start
const database = require('./pages/user/index');
app.use(database);

// Router finish

app.route('/').get((req, res) => {
    // const s = require("./pages/user/index.js")
    res.send(`
        <h1>Welcome to Okki Api Server</h1>
        `);
});
app.route('/ws').get((req, res) => {
    res.send(`
        <h1>Welcome to Okki WebSocket</h1>
        `);
});

const io = new Server(server,{
    cors: {
        origin: connectSocket,
        methods: ["GET", "POST"],
        transports: ['websocket', 'polling'],
        credentials: true
    },
    allowEIO3: true
})


io.of("/ws").on('connection',socket=>{
    const rooms = socket.handshake.query.c;
    if(rooms!==undefined){
        socket.join(rooms)
        socket.on("connectToRoom",(e)=>{
            console.log("Room name is "+e.text)
            socket.broadcast.to(rooms).emit("get_data",e);
        })
        socket.on("send_qustion",e=>{
            socket.broadcast.to(rooms).emit("get_question",e);
        })
    }
});

app.use((req, res, next) => {
    res.status(404).send("<h1>404 Error</h1><p>Sorry can't find that!</p>")
});

app.use((err, req, res, next) => {
    console.error(err.stack)
    res.status(500).send('<h1>500 Error</h1><p>Something broke!</p>')
});

server.listen(PORT,()=>{
    console.log("Server is running on port "+PORT);
})