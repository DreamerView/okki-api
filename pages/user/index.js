/*jshint esversion: 6 */
/*jshint esversion: 8 */

const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const knex = require("../knex/user");
const connection = require("../knex/mysql2");

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
    console.time('user/index jwt-token-update');
    const authHeader = String(req.headers.authorization),getToken = authHeader && authHeader.split(" ")[1],getClientId = authHeader && authHeader.split(" ")[2],token = aes.decrypt(getToken),clientId = aes.decrypt(getClientId),getTokens = await knex.raw('select `accessToken` from `usersToken` where clientId="'+clientId+'"');
    if(JSON.stringify(getTokens)==="[]") return timerStart(res.sendStatus(409));
    if(token===null) return timerStart(res.sendStatus(409));
    jwt.verify(token,process.env.ACCESS_TOKEN,async(err,uid)=>{
        if(err) return timerStart(res.sendStatus(406));
        req.uid = uid;
        return next();
    });
    console.timeEnd('user/index jwt-token-update');
};

router.get('/verify-user',authToken,async(req,res)=>{
    try {
        const uuid = req.uid.uuid;
        if(uuid!==undefined && uuid!==null) {
            return connection.execute('SELECT EXISTS(SELECT `uuid` FROM `users` WHERE `uuid` LIKE ? LIMIT 1)',['uuid',uuid],(err, results, fields) => {
                if(err) return res.sendStatus(409);
                return res.sendStatus(200); 
            });
        } else return timerStart(res.sendStatus(409));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/verify-user - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/get-devices',authToken,async(req,res)=>{
    try {
        const uuid = String(req.uid.uuid);
        console.time("/get-devices finished with");
        if(uuid!==undefined && uuid!==null) {
            // console.log(connection.exce)
            connection.execute('SELECT `clientId`,`clientInfo`,`getTime`,`ipInfo` FROM `'+uuid+'_usersToken`',(err, results, fields) => {
                return res.status(200).json({clientId:req.uid.clientId,result:results}); 
            });
            console.timeEnd("/get-devices finished with");
        } else return timerStart(res.sendStatus(409));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-devices - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/get-data',authToken,async(req,res)=>{
    try {
        console.time('/get-data finished with');
        const uuid = String(req.uid.uuid);
        if(uuid!==undefined && uuid!==null) {
            let cryptoKey,nameUser,surnameUser,dataUser,avatarUser,loginUser,clientUser;
            const getCrypto = await knex.raw("select `keyCrypto` from `usersKey` WHERE uuid='"+uuid+"'"),getDatabase = await knex.raw('select `name`,`surname`,`data`,`avatar`,`login`,`client` from `users` where uuid="'+uuid+'"');
            console.log(getCrypto)
            getCrypto[0].map(result=>cryptoKey=result.keyCrypto);
            getDatabase[0].map(result=>{nameUser=aes256({key:cryptoKey,method:"dec",text:result.name});surnameUser=aes256({key:cryptoKey,method:"dec",text:result.surname});dataUser=result.data;avatarUser=result.avatar;clientUser=result.client;loginUser=aes256({key:cryptoKey,method:"dec",text:result.login});});
            const httpCheck = req.hostname==='localhost'?'http://':"https://",portCheck = req.hostname==='localhost'?':'+process.env.PORT:"",avatarResult = clientUser==="okki"?httpCheck+req.hostname+portCheck+avatarUser:avatarUser;
            res.status(200).json({name:aes.encrypt(nameUser),surname:aes.encrypt(surnameUser),data:aes.encrypt(dataUser),avatar:aes.encrypt(avatarResult),login:aes.encrypt(loginUser)});
        } else return timerStart(res.sendStatus(409));
        console.timeEnd('/get-data finished with');
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-data - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

module.exports = router;
