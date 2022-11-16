const express = require('express');
const app = express();
const http = require('http');
const {Server} = require("socket.io");

const server = http.createServer(app);

app.get('/', (req, res) => {
    res.send(`
        <h1>Welcome to Okki Api Server</h1>
        `);
});
app.get('/ws', (req, res) => {
    res.send(`
        <h1>Welcome to Okki WebSocket</h1>
        `);
});

const io = new Server(server,{
    cors: {
        origin: "http://localhost:3000",
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
})

server.listen(3001,()=>{
    console.log("Server is running");
})