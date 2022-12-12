const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const knex = require('knex')({
    client: 'mysql2',
    connection: {
      host : process.env.DATABASE_HOST,
      port : process.env.DATABASE_PORT,
      user : process.env.DATABASE_USER,
      password : process.env.DATABASE_PASSWORD,
      database : 'okkikz_user'
    }
});
// import { SMTPClient } from 'emailjs';
var SMTPConnection = require('smtp-connection');
const nodemailer = require('nodemailer');
let transporter = nodemailer.createTransport({
    host: 'mail.okki.kz',
    port:993,
    secure:true,
    auth: {
        user: "support@okki.kz",
        pass: "!M2raumOp"
    }
})
const AesEncryption = require('aes-encryption');
const aes = new AesEncryption();
aes.setSecretKey(process.env.AES_KEY);

const sendEmail = () => {
    var connectionConfig = {
        host: 'mail.okki.kz', // remote SMTP server address
        port: 25,
        ignoreTLS: true,
        secure: false,
        authMethod: 'login', // can be 'LOGIN' or 'CRAM-MD5' if authentication is required
        
        //debug: true,
        
        // name: 'mylocalcomputer.provider.com' // local connection address (for EHLO message)
    };
    
    var connectionAuth = {
        user: 'support@okki.kz',
        pass: '!M2raumOp'
    };
    
    var sender = {
        name: 'Okki.kz', // please use [a-zA-Z0-9.- ]
        email: 'support@okki.kz'
    };
    
    var recipient = {
        name: 'Temirkhan', // please use [a-zA-Z0-9.- ]
        email: 'temirkhan.onyx@gmail.com'
    };
    
    // below you don't have to configure anything
    
    var now = new Date();
    var testMsg = 'From: '+sender.name+' <'+sender.email+'>\r\n'
        + 'To: '+recipient.name+' <'+recipient.email+'>\r\n'
        + 'Subject: Test message on '+now+'\r\n'
        + '\r\n'
        +'This is a test message\n\n'
        +'On '+now;
    
    var connection = new SMTPConnection(connectionConfig);
    
    connection.connect(function() {
        console.log('Connected');
        
        connection.login(connectionAuth, function(err) {
            if (err !== null) {
                console.log('login err: '+err);
            } else {
                console.log('Authenticated');
                
                var now = new Date();
                connection.send({
                    from: sender.email,
                    to: recipient.email
                }, testMsg, function(err) {
                    console.log('Message sent');
                    connection.quit();
                });
            }
        });
    });
    
    // works only if connectionConfig.debug === true
    connection.on('log', function(data) {
        console.dir(data);
    });
    
    connection.on('error', function(err) {
        console.log('Error occurred: '+err);
    });
}

const authToken = (req,res,next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];
    if(token==null) return res.sendStatus(401);

    jwt.verify(token,process.env.ACCESS_TOKEN,(err,uid)=>{
        if(err) return res.sendStatus(403);
        req.uid = uid;
        next()
    })
};

router.get('/forget',(req,res)=>{
    // let message = {
    //     from: '"Node js" <support@okki.kz>',
    //     to: "temirkhan.onyx@gmail.com",
    //     subject: "Subject",
    //     text: "Hello SMTP Email"
    // }
    // transporter.sendMail(message,function(err, info) {
    //     if (err) {
    //       console.log(err)
    //     } else {
    //       console.log(info);
    //     }
    // });
    sendEmail()
    res.send("Forget!")
})


router.get('/database-select',(req,res)=>{
    // console.log(router);
    // knex.raw("SELECT 1").then(() => {
    //     return "Connected"
    // }).catch(e=>{return "error"})
    let select_array = req.query.select!==undefined?req.query.select:"";
    knex.select(select_array).from("users").then(e=>{
        res.json(e)
    }).catch(e=>{res.send(e)});
});

router.post('/database-insert', (req, res) => {    
    console.log(req.body);  
    res.json(req.body);  
});

router.get("/select1",authToken,(req,res)=>{
    res.json("Yes you did it!");
})

router.post('/login', async(req, res) => {
    const uid =  aes.decrypt(req.body.email);
    const pass = aes.decrypt(req.body.password);
    console.log(uid);
    try {
        if(uid!==undefined) {
            const start = await knex.select("uuid","name","surname").where({email:uid}).andWhere({password:pass}).from("users")
            if(start.length == 0) {
                console.log("Not found");
                res.sendStatus(404);
            } else {
                start.map(result=>{
                    const AccessToken = jwt.sign({uid:result.uuid},process.env.ACCESS_TOKEN,{ expiresIn: '30s' });
                    res.json({accessToken:aes.encrypt(AccessToken),name:aes.encrypt(result.name),surname:aes.encrypt(result.surname)});
                    console.log("Exist: "+uid);
                    console.log("New token to "+uid+" is: "+AccessToken);
                });
            }
        }
    } catch {
        res.sendStatus(500);
    }
});
router.post('/token',(req,res) => {

})

module.exports = router;
