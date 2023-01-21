/*jshint esversion: 6 */
/*jshint esversion: 8 */

const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
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
    const authHeader = String(req.headers.authorization),getToken = authHeader && authHeader.split(" ")[1],getClientId = authHeader && authHeader.split(" ")[2],token = aes.decrypt(getToken),clientId = aes.decrypt(getClientId);
    connection.execute('SELECT `accessToken` FROM `usersToken` WHERE `clientId` = ? LIMIT 1',[clientId],(err, results, fields) => {
        if(results.length===0) return timerStart(res.sendStatus(409));
        if(token===null) return timerStart(res.sendStatus(409));
        jwt.verify(token,process.env.ACCESS_TOKEN,async(err,uid)=>{
            if(err) return timerStart(res.sendStatus(406));
            req.uid = uid;
            return next();
        });
    });
    console.timeEnd('user/index jwt-token-update');
};

router.get('/verify-user',authToken,async(req,res)=>{
    try {
        console.time('/verify-user finished with');
        const uuid = req.uid.uuid;
        if(uuid!==undefined || uuid!==null)
            return connection.execute('SELECT `uuid` FROM `users` WHERE `uuid` LIKE ? LIMIT 1',[uuid],(err, results, fields) => {
                if(results.length===0) return res.sendStatus(409);
                if(err) return res.sendStatus(409);
                console.timeEnd('/verify-user finished with');
                return res.status(200).json({uuid:uuid}); 
            });
        else return timerStart(res.sendStatus(409));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/verify-user - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/get-devices',authToken,async(req,res)=>{
    try {
        const uuid = String(req.uid.uuid);
        console.log(uuid);
        console.time("/get-devices finished with");
        if(uuid!==undefined || uuid!==null) {
            connection.execute('SELECT `clientId`,`clientInfo`,`getTime`,`ipInfo` FROM `'+uuid+'_usersToken`',(err, results, fields) => {
                if(err) res.sendStatus(409);
                else if(results) return res.status(200).json({clientId:req.uid.clientId,result:results}); 
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
        if(uuid!==undefined || uuid!==null) {
            connection.execute('select `keyCrypto` from `usersKey` WHERE uuid= ? LIMIT 1',[uuid],(err, results, fields) => {
                if(results.length===0) return res.sendStatus(409);
                results.map(event=>{
                    const cryptoKey = event.keyCrypto;
                    connection.execute('select `name`,`surname`,`data`,`avatar`,`login` from `users` where uuid=? LIMIT 1',[uuid],(err, results, fields) => {
                        results.map(result=>{
                            const nameUser=aes256({key:cryptoKey,method:"dec",text:result.name}),surnameUser=aes256({key:cryptoKey,method:"dec",text:result.surname}),dataUser=result.data,avatarUser=result.avatar,loginUser=aes256({key:cryptoKey,method:"dec",text:result.login});
                            const httpCheck = req.hostname==='localhost'?'http://':"https://",portCheck = req.hostname==='localhost'?':'+process.env.PORT:"",avatarResult = avatarUser.slice(0,5)!=="https"?httpCheck+req.hostname+portCheck+avatarUser:avatarUser;
                            return res.status(200).json({name:aes.encrypt(nameUser),surname:aes.encrypt(surnameUser),data:aes.encrypt(dataUser),avatar:aes.encrypt(avatarResult),login:aes.encrypt(loginUser)});
                        })
                    })
                })
            })
        } else return timerStart(res.sendStatus(409));
        console.timeEnd('/get-data finished with');
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-data - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

module.exports = router;
