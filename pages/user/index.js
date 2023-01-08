/*jshint esversion: 6 */
/*jshint esversion: 8 */

const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
// const knex = require('knex')({
//     client: 'mysql2',
//     connection: {
//       host : process.env.DATABASE_HOST,
//       port : process.env.DATABASE_PORT,
//       user : process.env.DATABASE_USER,
//       password : process.env.DATABASE_PASSWORD,
//       database : process.env.DATABASE_NAME_USERS,
//     },
//     pool: {
//       min: 0,
//       max: 7
//     }
// });


const aes256 = ({key,method,text}) => {
    const chipherEncryption = require('aes-encryption');
    const chipher = new chipherEncryption();
    chipher.setSecretKey(key);
    const result = text;
    if(method==="enc") {
        return chipher.encrypt(result);
    } else if(method==="dec") {
        return chipher.decrypt(result);
    }
};

const AesEncryption = require('aes-encryption');
const aes = new AesEncryption();
aes.setSecretKey(process.env.AES_KEY);

const timerStart = (event) => {
    return setTimeout(()=>event,[500]);
};

const authToken = async(req,res,next) => {
    const knex = require('knex')({
        client: 'mysql2',
        connection: {
          host : process.env.DATABASE_HOST,
          port : process.env.DATABASE_PORT,
          user : process.env.DATABASE_USER,
          password : process.env.DATABASE_PASSWORD,
          database : process.env.DATABASE_NAME_USERS,
        }
    });
    const authHeader = req.headers['authorization'];
    const getToken = authHeader && authHeader.split(" ")[1];
    const getClientId = authHeader && authHeader.split(" ")[2];
    const token = aes.decrypt(getToken);
    const clientId = aes.decrypt(getClientId);
    const getTokens = await knex.select("accessToken").where({clientId:clientId}).from("usersToken");
    knex.destroy();
    if(JSON.stringify(getTokens)==="[]") return timerStart(res.sendStatus(409));
    if(token===null) return timerStart(res.sendStatus(409));
    jwt.verify(token,process.env.ACCESS_TOKEN,async(err,uid)=>{
        if(err) return timerStart(res.sendStatus(406));
        req.uid = uid;
        next();
    });
};



// router.get('/database-select',authToken,async(req,res)=>{
//     try {
//         console.log(req.uid.uuid);
//         let select_array = req.query.select!==undefined?req.query.select:"";
//         const getDatabase = await knex.select(select_array).from("users");
//         res.json(getDatabase);
//     } catch(e) {
//         console.log('\x1b[31m%s\x1b[0m',"/database-select - Mistake, mistake is ");
//         console.log(e);
//         return res.sendStatus(500);
//     }
// });

router.get('/get-devices',authToken,async(req,res)=>{
    try {
        const uuid = req.uid.uuid;
        if(uuid!==undefined || uuid!==null) {
            const knex = require('knex')({
                client: 'mysql2',
                connection: {
                  host : process.env.DATABASE_HOST,
                  port : process.env.DATABASE_PORT,
                  user : process.env.DATABASE_USER,
                  password : process.env.DATABASE_PASSWORD,
                  database : process.env.DATABASE_NAME_USERS,
                }
            });
            const result = await knex.select('clientId','clientInfo','getTime','ipInfo').from(uuid+"_usersToken");
            // console.log(result);
            res.json({clientId:req.uid.clientId,result:result});
            knex.destroy();
        } else return timerStart(res.sendStatus(406));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-devices - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/get-data',authToken,async(req,res)=>{
    try {
        const uuid = req.uid.uuid;
        if(uuid!==undefined || uuid!==null) {
            const knex = require('knex')({
                client: 'mysql2',
                connection: {
                  host : process.env.DATABASE_HOST,
                  port : process.env.DATABASE_PORT,
                  user : process.env.DATABASE_USER,
                  password : process.env.DATABASE_PASSWORD,
                  database : process.env.DATABASE_NAME_USERS,
                }
            });
            let cryptoKey;
            const getCrypto = await knex.select('keyCrypto').from("usersKey").where({uuid:uuid});
            getCrypto.map(result=>cryptoKey=result['keyCrypto']);
            let select_array = req.query.select!==undefined?req.query.select:"";
            const getDatabase = await knex.select("name","surname","data","avatar","login","client").from("users").where("uuid",uuid);
            knex.destroy();
            let nameUser,surnameUser,dataUser,avatarUser,loginUser,clientUser;
            getDatabase.map(result=>{nameUser=aes256({key:cryptoKey,method:"dec",text:result['name']});surnameUser=aes256({key:cryptoKey,method:"dec",text:result['surname']});dataUser=result['data'];avatarUser=result['avatar'];clientUser=result['client'];loginUser=aes256({key:cryptoKey,method:"dec",text:result['login']})})
            const httpCheck = req.hostname==='localhost'?'http://':"https://";
            const portCheck = req.hostname==='localhost'?':'+process.env.PORT:"";
            const avatarResult = clientUser==="okki"?httpCheck+req.hostname+portCheck+avatarUser:avatarUser;
            res.json({name:aes.encrypt(nameUser),surname:aes.encrypt(surnameUser),data:aes.encrypt(dataUser),avatar:aes.encrypt(avatarResult),login:aes.encrypt(loginUser)});
        } else return timerStart(res.sendStatus(406));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-data - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

module.exports = router;
