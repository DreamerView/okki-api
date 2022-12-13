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
      database : 'users',
    }
});

const generatePassword = () => {
    var length = 4,
        charset = "0123456789",
        retVal = "";
    for (var i = 0, n = charset.length; i < length; ++i) {
        retVal += charset.charAt(Math.floor(Math.random() * n));
    }
    return retVal;
};

const emailForm = ({title,password}) => {return(`
<div style="margin:32px auto;width: 80%;padding:32px;border-radius: 24px;border:1px solid #e3e5e8;">
        <img src="https://okki-data.object.pscloud.io/okki.png" alt="Logo" title="Logo" style="display:block;margin:0 auto;border-radius: 24px;" width="250" height="100" />
        <h2 style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;text-align: center;margin-top:40px;color:#000000">${title}</h2>
        <div style="margin:24px auto;width: 300px;border-radius: 24px;border:1px solid #e3e5e8;">
            <h1 style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;text-align: center;margin-top:24px;color:#000000;font-size:40px">${password}</h1>
        </div>
        <p style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;text-align: center;margin-top:24px;color:#000000">Here is your OTP verification code.</p>
        <p style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;text-align: center;margin-top:24px;color:#000000">It will expire in 6 minuters.</p>
    </div>
`)};
const nodemailer = require('nodemailer');
let transporter = nodemailer.createTransport({
    host: 'w3.okki.kz',
    port: 465,
    auth: {
        user: "support@w3.okki.kz",
        pass: "!M2raumOp"
    },
})
const AesEncryption = require('aes-encryption');
const aes = new AesEncryption();
aes.setSecretKey(process.env.AES_KEY);

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

router.post('/forget',async(req,res)=>{
    try {
        const uid =  aes.decrypt(req.body.email);
        if(uid!==undefined) {
            const start = await knex.select("email","uuid",'otp').where({email:uid}).from("users")
            if(start.length == 0) {
                res.sendStatus(404); // User not found
            } else {
                const otp_key = generatePassword();
                // let message = {
                //     from: '"Okki.kz" <support@okki.kz>',
                //     to: uid,
                //     subject: "Verification code to reset password",
                //     html:emailForm({title:"Verification Code",password:otp_key}),
                // }
                // transporter.sendMail(message,function(err, info) {
                //     if (err) {
                //     console.log(err)
                //     } else {
                //     console.log(info);
                //     }
                // });
                start.map(async(result)=>{
                    const upd = await knex("users").where({uuid:result.uuid}).update({otp:otp_key});
                });
                res.json({success:true});
            }
        }
    } catch(e) {
        res.sendStatus(500);
    }
});

router.post('/reset-password-otp',async(req,res)=>{
    try {
        const otp = req.body.otp;
        const email = aes.decrypt(req.body.email);
        let start = await knex.select("uuid").where({email:email}).andWhere({otp:otp}).from('users')
        if(start.length===0) {
            res.sendStatus(404);
        } else {
            res.json({success:true})
        }
    } catch {
        res.sendStatus(500);
    }
})

router.get('/database-select',(req,res)=>{
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
    try {
        const uid =  aes.decrypt(req.body.email);
        const pass = aes.decrypt(req.body.password);
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
