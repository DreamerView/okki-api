/*jshint esversion: 6 */
/*jshint esversion: 8 */

const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const knex = require("../knex/user");

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
    const authHeader = req.headers.authorization,getToken = authHeader && authHeader.split(" ")[1],getClientId = authHeader && authHeader.split(" ")[2],token = aes.decrypt(getToken),clientId = aes.decrypt(getClientId),getTokens = await knex.select("accessToken").where({clientId:clientId}).from("usersToken");
    if(JSON.stringify(getTokens)==="[]") return timerStart(res.sendStatus(409));
    if(token===null) return timerStart(res.sendStatus(409));
    jwt.verify(token,process.env.ACCESS_TOKEN,async(err,uid)=>{
        if(err) return timerStart(res.sendStatus(406));
        req.uid = uid;
        next();
    });
    console.timeEnd('user/index jwt-token-update');
};
router.get('/get-devices',authToken,async(req,res)=>{
    try {
        const uuid = req.uid.uuid;
        console.time("/get-devices finished with");
        if(uuid!==undefined && uuid!==null) {
            const result = await knex.select('clientId','clientInfo','getTime','ipInfo').from(uuid+"_usersToken");
            res.status(200).json({clientId:req.uid.clientId,result:result});
        } else return timerStart(res.sendStatus(406));
        console.timeEnd("/get-devices finished with");
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-devices - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/get-data',authToken,async(req,res)=>{
    try {
        console.time('/get-data finished with');
        const uuid = req.uid.uuid;
        if(uuid!==undefined && uuid!==null) {
            let cryptoKey,nameUser,surnameUser,dataUser,avatarUser,loginUser,clientUser;
            const getCrypto = await knex.select('keyCrypto').from("usersKey").where({uuid:uuid}),getDatabase = await knex.select("name","surname","data","avatar","login","client").from("users").where("uuid",uuid);
            getCrypto.map(result=>cryptoKey=result.keyCrypto);
            getDatabase.map(result=>{nameUser=aes256({key:cryptoKey,method:"dec",text:result.name});surnameUser=aes256({key:cryptoKey,method:"dec",text:result.surname});dataUser=result.data;avatarUser=result.avatar;clientUser=result.client;loginUser=aes256({key:cryptoKey,method:"dec",text:result.login});});
            const httpCheck = req.hostname==='localhost'?'http://':"https://",portCheck = req.hostname==='localhost'?':'+process.env.PORT:"",avatarResult = clientUser==="okki"?httpCheck+req.hostname+portCheck+avatarUser:avatarUser;
            res.status(200).json({name:aes.encrypt(nameUser),surname:aes.encrypt(surnameUser),data:aes.encrypt(dataUser),avatar:aes.encrypt(avatarResult),login:aes.encrypt(loginUser)});
        } else return timerStart(res.sendStatus(406));
        console.timeEnd('/get-data finished with');
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/get-data - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

module.exports = router;
