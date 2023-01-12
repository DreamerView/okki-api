/*jshint esversion: 6 */
/*jshint esversion: 8 */
/*jshint esversion: 10 */

const jwt = require('jsonwebtoken');
const express = require('express');
const router = express.Router();
const axios = require('axios');

const timerStart = (event) => {
    return setTimeout(()=>event,[500]);
};

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
`);
};
const nodemailer = require('nodemailer');
let transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    auth: {
        user: process.env.SMTP_AUTH_USER,
        pass: process.env.SMTP_AUTH_PASS
    },
});
const AesEncryption = require('aes-encryption');
const aes = new AesEncryption();
aes.setSecretKey(process.env.AES_KEY);

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

const generateAccessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '7m' });
};
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN);
};

const authToken = async(req,res,next) => {
    const authHeader = req.headers.authorization;
    const getToken = authHeader && authHeader.split(" ")[1];
    const getClientId = authHeader && authHeader.split(" ")[2];
    const token = aes.decrypt(getToken);
    const clientId = aes.decrypt(getClientId);
    const knex = require('knex')(require('../knex/user'));
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


router.post('/signin-with-socialnetwork',async(req,res)=>{
    try {
        console.log("sds");
        const social = ['Google'];
        const email =  aes.decrypt(req.body.email);
        const all = aes.decrypt(req.body.name);
        const image = aes.decrypt(req.body.image);
        const client = aes.decrypt(req.body.client);
        const name = all.split(" ")[0]===undefined||all.split(" ")[0]===null?" ":all.split(" ")[0];
        const surname = all.split(" ")[1]===undefined||all.split(" ")[1]===null?" ":all.split(" ")[1];
        const clientInfo = aes.decrypt(req.body.clientInfo);
        const getIp = aes.decrypt(req.body.getIp);
        console.log(name+" "+surname);
        if(email!==undefined) {
            if(social.includes(client)) {
                const knex = require('knex')(require('../knex/user'));
                const getClient = await knex.select("uuid").where({email:email,client:client}).from("users");
                if(JSON.stringify(getClient)==="[]") {
                    const ipParams = await axios.get("https://freeipapi.com/api/json/"+getIp);
                    const ipInfo = JSON.stringify({ip:getIp,countryName:ipParams.data.countryName,countryCode:ipParams.data.countryCode,cityName:ipParams.data.cityName,reqionName:ipParams.data.reqionName});
                    const {v4: uuidv4} = require('uuid');
                    const data = String(Date.now());
                    const uuid = data+"-"+uuidv4();
                    const clientId = data+"-"+uuidv4();
                    const keyCrypto = require('crypto').randomBytes(32).toString('hex');
                    const count = await knex('users').count('*');
                    let id;
                    count.map(result=>id=result['count(*)']);
                    const newId = Number(id)+1;
                    const loginUser = "user-"+newId;
                    const accessTokenGeneration = generateAccessToken({uuid:uuid,clientId:clientId});
                    const refreshTokenGeneration = generateRefreshToken({uuid:uuid,clientId:clientId});
                    const loginResult = aes256({key:keyCrypto,method:"enc",text:loginUser});
                    const nameResult = aes256({key:keyCrypto,method:"enc",text:name});
                    const surnameResult = aes256({key:keyCrypto,method:"enc",text:surname});
                    const usersStart = await knex('users').insert({uuid:uuid,login:loginResult,email:email,password:null,name:nameResult,surname:surnameResult,data:data,avatar:image,client:client});
                        await knex('usersKey').insert({uuid:uuid,keyCrypto:keyCrypto});
                        if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                            await knex.schema.createTable(uuid+'_usersToken', function(table) {
                                table.string('clientId').primary();
                                table.text('getTime');
                                table.text('ipInfo');
                                table.text('clientInfo');
                                table.text('accessToken');
                                table.text('refreshToken');
                            });
                        }
                        await knex(uuid+'_usersToken').insert({clientId:clientId,getTime:data,ipInfo:ipInfo,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
                        await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
                        timerStart(JSON.stringify(usersStart)!=="[]"&&res.json({success:true,accessToken:aes.encrypt(accessTokenGeneration),name:aes.encrypt(name),surname:aes.encrypt(surname),avatar:aes.encrypt(image),clientId:aes.encrypt(clientId)}));
                        knex.destroy();
                        console.log('\x1b[32m%s\x1b[0m',"№"+newId+") Registered new user "+email);
                } else {
                    const ipParams = await axios.get("https://freeipapi.com/api/json/"+getIp);
                    const ipInfo = JSON.stringify({ip:getIp,countryName:ipParams.data.countryName,countryCode:ipParams.data.countryCode,cityName:ipParams.data.cityName,reqionName:ipParams.data.reqionName});
                    const {v4: uuidv4} = require('uuid');
                    const data = String(Date.now());
                    const clientId = data+"-"+uuidv4();
                    let uuid;
                    getClient.map(result=>uuid=result.uuid);
                    const accessTokenGeneration = generateAccessToken({uuid:uuid,clientId:clientId});
                    const refreshToken = generateRefreshToken({uuid:uuid,clientId:clientId});
                    if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                        await knex.schema.createTable(uuid+'_usersToken', function(table) {
                            table.string('clientId').primary();
                            table.text('getTime');
                            table.text('ipInfo');
                            table.text('clientInfo');
                            table.text('accessToken');
                            table.text('refreshToken');
                        });
                    }
                    await knex(uuid+'_usersToken').insert({clientId:clientId,getTime:data,ipInfo:ipInfo,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshToken});
                    await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:accessTokenGeneration,refreshToken:refreshToken});
                    timerStart(res.json({accessToken:aes.encrypt(accessTokenGeneration),name:aes.encrypt(name),surname:aes.encrypt(surname),avatar:aes.encrypt(image),clientId:aes.encrypt(clientId)}));
                    knex.destroy();
                    console.log("Exist: "+uuid);
                    console.log("New token to "+uuid+" is: "+accessTokenGeneration);
                }
                knex.destroy();
            } 
            else timerStart(res.sendStatus(404));

        }
    }
    catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/signin-with-socialnetwork - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.get('/signout',authToken,async(req,res)=>{
    try {
        const knex = require('knex')(require('../knex/user'));
        const first = await knex(req.uid.uuid+"_usersToken").del().where({clientId:req.uid.clientId});
        const second = await knex('usersToken').del().where({clientId:req.uid.clientId,uuid:req.uid.uuid});
        knex.destroy();
        if(JSON.stringify(first)!=="[]"&&JSON.stringify(second)!=="[]") return res.json({accept:true});
        else res.sendStatus(409);
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/signout - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/signout-device',authToken,async(req,res)=>{
    const clientId = req.body.clientId;
    try {
        const knex = require('knex')(require('../knex/user'));
        const first = await knex(req.uid.uuid+"_usersToken").del().where({clientId:clientId});
        const second = await knex('usersToken').del().where({clientId:clientId,uuid:req.uid.uuid});
        knex.destroy();
        if(JSON.stringify(first)!=="[]"&&JSON.stringify(second)!=="[]") return timerStart(res.json({accept:true}));
        else timerStart(res.sendStatus(409));
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/signout-device - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/signin', async(req, res) => {
    try {
        const uid =  aes.decrypt(req.body.email);
        const pass = aes.decrypt(req.body.password);
        const client = aes.decrypt(req.body.client);
        const clientInfo = aes.decrypt(req.body.clientInfo);
        const getIp = aes.decrypt(req.body.getIp);
        if(uid!==undefined) {
            let uuidReq,passwordReq,cryptoKey;
            const knex = require('knex')(require('../knex/user'));
            const getUUID = await knex.select("uuid","password").where({email:uid,client:client}).from("users");
            if(JSON.stringify(getUUID)==="[]") {res.sendStatus(404);knex.destroy();}
            else {
                getUUID.map(result=>{uuidReq=result.uuid;passwordReq=result.password;});
                const getCrypto = await knex.select("keyCrypto").where({uuid:uuidReq}).from("usersKey");
                getCrypto.map(result=>cryptoKey=result.keyCrypto);
                const password = aes256({key:cryptoKey,method:"dec",text:passwordReq});
                if(pass===password) {
                    const start = await knex.select("uuid","name","surname","avatar").where({email:uid,client:"okki"}).from("users");
                    if(start.length === 0) {
                        res.sendStatus(404);
                        knex.destroy();
                    } else {
                        start.map(async(result)=>{
                            const ipParams = await axios.get("https://freeipapi.com/api/json/"+getIp,{
                                headers: {
                                  'Cache-Control': 'no-cache',
                                  'Pragma': 'no-cache',
                                  'Expires': '0',
                                },
                            });
                            const ipInfo = JSON.stringify({ip:getIp,countryName:ipParams.data.countryName,countryCode:ipParams.data.countryCode,cityName:ipParams.data.cityName,reqionName:ipParams.data.reqionName});
                            const {v4: uuidv4} = require('uuid');
                            const data = String(Date.now());
                            const clientId = data+"-"+uuidv4();
                            const uuid = result.uuid;
                            const accessTokenGeneration = generateAccessToken({uuid:uuid,clientId:clientId});
                            const refreshToken = generateRefreshToken({uuid:uuid,clientId:clientId});
                            const avatarUser = result.avatar;
                            const httpCheck = req.hostname==='localhost'?'http://':"https://";
                            const portCheck = req.hostname==='localhost'?':'+process.env.PORT:"";
                            const avatarResult = httpCheck+req.hostname+portCheck+avatarUser;
                            if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                                await knex.schema.createTable(uuid+'_usersToken', function(table) {
                                    table.string('clientId').primary();
                                    table.text('getTime');
                                    table.text('ipInfo');
                                    table.text('clientInfo');
                                    table.text('accessToken');
                                    table.text('refreshToken');
                                });
                            }
                            await knex(uuid+'_usersToken').insert({clientId:clientId,ipInfo:ipInfo,getTime:data,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshToken});
                            await knex('usersToken').insert({uuid:uuid,accessToken:accessTokenGeneration,refreshToken:refreshToken,clientId:clientId});
                            res.json({accessToken:aes.encrypt(accessTokenGeneration),name:aes.encrypt(aes256({key:cryptoKey,method:"dec",text:result.name})),surname:aes.encrypt(aes256({key:cryptoKey,method:"dec",text:result.surname})),avatar:aes.encrypt(avatarResult),clientId:aes.encrypt(clientId)});
                            knex.destroy();
                            console.log("Exist: "+uid);
                            console.log("New token to "+uid+" is: "+accessTokenGeneration);
                        });
                    }
                } else {
                    timerStart(res.sendStatus(404));
                }
            }
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/signin - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/forget',async(req,res)=>{
    try {
        const uid =  aes.decrypt(req.body.email);
        const client =  aes.decrypt(req.body.client);
        if(uid!==undefined) {
            const knex = require('knex')(require('../knex/user'));
            const start = await knex.select("email","uuid",'otp').where({email:uid,client:client}).from("users");
            if(start.length == 0) {
                res.sendStatus(404);
                knex.destroy();
            } else {
                const otp_key = generatePassword();
                // let message = {
                //     from: '"Okki.kz" <support@okki.kz>',
                //     to: uid,
                //     subject: "Verification code to reset password",
                //     html:emailForm({title:"Verification Code",password:otp_key}),
                // };
                // transporter.sendMail(message,function(err, info) {
                //     if (err) console.log(err);
                //     else console.log(info);
                // });
                start.map(async(result)=>{
                    await knex("users").where({uuid:result.uuid}).update({otp:otp_key});
                });
                res.json({success:true});
                knex.destroy();
            }
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/forget - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/verify-email',async(req,res)=>{
    try {
        const uid =  aes.decrypt(req.body.email);
        const client =  aes.decrypt(req.body.client);
        if(uid!==undefined) {
            const knex = require('knex')(require('../knex/user'));
            const start = await knex.select("name","surname","avatar","uuid","email").where({email:uid,client:client}).from("users");
            if(start.length === 0) {
                res.sendStatus(404);
                knex.destroy();
            } else {
                let name,surname,avatar,uuid,email;
                start.map(e=>{name=e.name;surname=e.surname;avatar=e.avatar;uuid=e.uuid;email=e.email;});
                const getCrypto = await knex.select("keyCrypto").where({uuid:uuid}).from("usersKey");
                let keyCrypto;
                getCrypto.map(e=>keyCrypto=e.keyCrypto);
                const nameResult = aes256({key:keyCrypto,method:"dec",text:name});
                const surnameResult = aes256({key:keyCrypto,method:"dec",text:surname});
                const httpCheck = req.hostname==='localhost'?'http://':"https://";
                const portCheck = req.hostname==='localhost'?':'+process.env.PORT:"";
                const avatarResult = client==="okki"?httpCheck+req.hostname+portCheck+avatar:avatar;
                timerStart(res.json({success:true,name:aes.encrypt(nameResult),surname:aes.encrypt(surnameResult),avatar:aes.encrypt(avatarResult),email:aes.encrypt(email)}));
                knex.destroy();
            }
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/verify-email - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/verify-email-otp',async(req,res)=>{
    try {
        const uid =  aes.decrypt(req.body.email);
        const client =  aes.decrypt(req.body.client);
        if(uid!==undefined) {
            const knex = require('knex')(require('../knex/user'));
            const start = await knex.select("email","uuid",'otp').where({email:uid,client:client}).from("users");
            if(start.length == 0) {
                const otp_key = generatePassword();
                let message = {
                    from: '"Okki.kz" <support@okki.kz>',
                    to: uid,
                    subject: "Verification account on Okki.kz",
                    html:emailForm({title:"Verification Code",password:otp_key}),
                };
                transporter.sendMail(message,function(err, info) {
                    if (err) console.log(err);
                    else console.log(info);
                });
                timerStart(res.json({otp:aes.encrypt(otp_key),success:true}));
                knex.destroy();
            } else {
                timerStart(res.sendStatus(404));
                knex.destroy();
            }
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/verify-email-otp - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});



router.post('/reset-password-otp',async(req,res)=>{
    try {
        const otp = req.body.otp;
        const email = aes.decrypt(req.body.email);
        const knex = require('knex')(require('../knex/user'));
        const start = await knex.select("uuid").where({email:email}).andWhere({otp:otp}).from('users');
        knex.destroy();
        if(start.length===0) timerStart(res.sendStatus(404));
        else res.json({success:true});
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/reset-password-otp - Mistake, mistake is ");
        console.log(e);
        return timerStart(res.sendStatus(500));
    }
});

router.post('/generate-token',async(req,res) => {
    try {
        const getClientId = aes.decrypt(req.body.clientId);
        if(getClientId!==undefined) {
            const knex = require('knex')(require('../knex/user'));
            const refreshToken = await knex.select("refreshToken","uuid").where({clientId:getClientId}).from("usersToken");
            const refreshTokens = await knex.select("refreshToken").from("usersToken");
            if(JSON.stringify(refreshToken)==="[]") {console.log("Not found token!");timerStart(res.sendStatus(409));}
            else if(JSON.stringify(refreshTokens)==="[]") {console.log("Not found tokens!");timerStart(res.sendStatus(409));}
            else {
                console.log("all okey");
                let getRefreshToken = null;
                let uuid = null;
                let getRefreshTokens = [];
                refreshToken.map((result)=>{getRefreshToken = result.refreshToken;uuid = result.uuid;});
                refreshTokens.map((result)=>getRefreshTokens.push(result.refreshToken));
                if (getRefreshToken === null) return timerStart(res.sendStatus(409));
                if (!getRefreshTokens.includes(getRefreshToken)) {console.log("Error2 is here");return timerStart(res.sendStatus(409));}

                    console.log("clientId: "+getClientId);
                    const accessTokenGeneration = generateAccessToken({uuid:uuid,clientId:getClientId});
                    const upd = await knex("usersToken").where({uuid:uuid,clientId:getClientId}).update({accessToken:accessTokenGeneration});
                    const upd1 = await knex(uuid+'_usersToken').where({clientId:getClientId}).update({accessToken:accessTokenGeneration});
                    console.log(upd+" "+upd1);
                    if(upd===1&&upd1===1) {
                        const access = aes.encrypt(accessTokenGeneration);
                        const clientIdResult = aes.encrypt(getClientId);
                        console.warn('updated!');
                        return timerStart(res.json({ accessToken: access,clientId:clientIdResult }));
                    } else {
                        console.log("Error!");
                        return timerStart(res.sendStatus(409));
                    }
            }
            knex.destroy();
        }
        else return res.sendStatus(409);
    }
    catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/generate-token - Mistake, mistake is ");
        console.log(e);
        return setTimeout(()=>res.sendStatus(500),[500]);
    }
});
router.post('/register-id',async(req,res)=>{
    try {
        const name = aes.decrypt(req.body.name);
        const surname = aes.decrypt(req.body.surname);
        const email = aes.decrypt(req.body.email);
        const password = aes.decrypt(req.body.password);
        const client = aes.decrypt(req.body.client);
        const clientInfo = aes.decrypt(req.body.clientInfo);
        const getIp = aes.decrypt(req.body.getIp);
        const knex = require('knex')(require('../knex/user'));
        const start = await knex.select("email").where({email:email,client:client}).from("users");
        if(start.length == 0) {
            const ipParams = await axios.get("https://freeipapi.com/api/json/"+getIp);
            const ipInfo = JSON.stringify({ip:getIp,countryName:ipParams.data.countryName,countryCode:ipParams.data.countryCode,cityName:ipParams.data.cityName,reqionName:ipParams.data.reqionName});
            const {v4: uuidv4} = require('uuid');
            const data = String(Date.now());
            const uuid = data+"-"+uuidv4();
            const clientId = data+"-"+uuidv4();
            const keyCrypto = require('crypto').randomBytes(32).toString('hex');
            const count = await knex('users').count('*');
            let id;
            count.map(result=>id=result['count(*)']);
            const newId = Number(id)+1;
            const loginUser = "user-"+newId;
            const accessTokenGeneration = generateAccessToken({uuid:uuid,clientId:clientId});
            const refreshTokenGeneration = generateRefreshToken({uuid:uuid,clientId:clientId});
            await knex('users').insert({uuid:uuid,login:aes256({key:keyCrypto,method:"enc",text:loginUser}),email:email,password:aes256({key:keyCrypto,method:"enc",text:password}),name:aes256({key:keyCrypto,method:"enc",text:name}),surname:aes256({key:keyCrypto,method:"enc",text:surname}),data:data,avatar:"/images/unknown.webp",client:client});
            await knex('usersKey').insert({uuid:uuid,keyCrypto:keyCrypto});
            if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                await knex.schema.createTable(uuid+'_usersToken', function(table) {
                    table.string('clientId').primary();
                    table.text('getTime');
                    table.text('ipInfo');
                    table.text('clientInfo');
                    table.text('accessToken');
                    table.text('refreshToken');
                });
            }
            await knex(uuid+'_usersToken').insert({clientId:clientId,ipInfo:ipInfo,getTime:data,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
            await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
            res.json({success:true,accessToken:aes.encrypt(accessTokenGeneration),clientId:aes.encrypt(clientId)});
            console.log('\x1b[32m%s\x1b[0m',"№"+newId+") Registered new user "+email);
            knex.destroy();
        } else {
            timerStart(res.json({email:true}));
            knex.destroy();
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/register-id - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});


module.exports = router;
