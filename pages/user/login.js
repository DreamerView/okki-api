/*jshint esversion: 6 */
/*jshint esversion: 8 */
/*jshint esversion: 10 */

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
      database : process.env.DATABASE_NAME_USERS,
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
    return jwt.sign(user, process.env.ACCESS_TOKEN, { expiresIn: '1m' });
};
const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN);
};

const authToken = async(req,res,next) => {
    const authHeader = req.headers['authorization'];
    const getToken = authHeader && authHeader.split(" ")[1];
    console.log(getToken);
    const token = aes.decrypt(getToken);
    const getTokens = await knex.select("accessToken").where({accessToken:token}).from("usersToken");
    if(JSON.stringify(getTokens)==="[]") return res.sendStatus(409);
    if(token==null) return res.sendStatus(409);
    jwt.verify(token,process.env.ACCESS_TOKEN,async(err,uid)=>{
        if(err) return res.sendStatus(406);
        req.uid = uid;
        next();
    });
};


router.post('/signin-with-socialnetwork',async(req,res)=>{
    try {
        console.log("sds")
        const social = ['Google'];
        const email =  aes.decrypt(req.body.email);
        const all = aes.decrypt(req.body.name);
        const image = aes.decrypt(req.body.image);
        const client = aes.decrypt(req.body.client);
        const name = all.split(" ")[0]===undefined||all.split(" ")[0]===null?" ":all.split(" ")[0];
        const surname = all.split(" ")[1]===undefined||all.split(" ")[1]===null?" ":all.split(" ")[1];
        const clientInfo = aes.decrypt(req.body.clientInfo);
        if(email!==undefined) {
            if(social.includes(client)) {
                const getClient = await knex.select("uuid").where({email:email,client:client}).from("users");
                console.log(email,client)
                if(JSON.stringify(getClient)==="[]") {
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
                    const checkEmail = await knex.select("uuid").where({email:email,client:client}).from("users");
                    // if(JSON.stringify(checkEmail)==="[]") {
                        const usersStart = await knex('users').insert({uuid:uuid,login:loginResult,email:email,password:null,name:nameResult,surname:surnameResult,data:data,avatar:image,client:client});
                        const cryptoStart = await knex('usersKey').insert({uuid:uuid,keyCrypto:keyCrypto});
                        if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                            await knex.schema.createTable(uuid+'_usersToken', function(table) {
                                table.string('clientId').primary();
                                table.text('getTime');
                                table.text('clientInfo');
                                table.text('accessToken');
                                table.text('refreshToken');
                            });
                        }
                        const tokenStart = await knex(uuid+'_usersToken').insert({clientId:clientId,getTime:data,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
                        const tokenInsert = await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
                        JSON.stringify(usersStart)!=="[]"&&res.json({success:true,accessToken:aes.encrypt(accessTokenGeneration),name:aes.encrypt(name),surname:aes.encrypt(surname),avatar:aes.encrypt(image)})
                        console.log('\x1b[32m%s\x1b[0m',"№"+newId+") Registered new user "+email);
                    // }
                } else {
                    const {v4: uuidv4} = require('uuid');
                    const data = String(Date.now());
                    const clientId = data+"-"+uuidv4();
                    console.log('exist')
                    let uuid;
                    getClient.map(result=>uuid=result.uuid);
                    const AccessToken = generateAccessToken({uuid:uuid,clientId:clientId});
                    const refreshToken = generateRefreshToken({uuid:uuid,clientId:clientId});
                    if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                        await knex.schema.createTable(uuid+'_usersToken', function(table) {
                            table.string('clientId').primary();
                            table.text('getTime');
                            table.text('clientInfo');
                            table.text('accessToken');
                            table.text('refreshToken');
                        });
                    }
                    const tokenStart = await knex(uuid+'_usersToken').insert({clientId:clientId,getTime:data,clientInfo:clientInfo,accessToken:AccessToken,refreshToken:refreshToken});
                    const tokenInsert = await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:AccessToken,refreshToken:refreshToken});
                    res.json({accessToken:aes.encrypt(AccessToken),name:aes.encrypt(name),surname:aes.encrypt(surname),avatar:aes.encrypt(image)});
                    console.log("Exist: "+uuid);
                    console.log("New token to "+uuid+" is: "+AccessToken);
                }
            } 
            else res.sendStatus(404);

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
        const first = await knex(req.uid.uuid+"_usersToken").del().where({clientId:req.uid.clientId});
        const second = await knex('usersToken').del().where({clientId:req.uid.clientId,uuid:req.uid.uuid});
        if(JSON.stringify(first)!=="[]"&&JSON.stringify(second)!=="[]") return res.send({accept:true});
        else res.sendStatus(403);
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/signout - Mistake, mistake is ");
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
        if(uid!==undefined) {
            let uuidReq,passwordReq,cryptoKey;
            const getUUID = await knex.select("uuid","password").where({email:uid,client:client}).from("users");
            if(JSON.stringify(getUUID)==="[]") res.sendStatus(404);
            else {
                getUUID.map(result=>{uuidReq=result["uuid"];passwordReq=result["password"]});
                const getCrypto = await knex.select("keyCrypto").where({uuid:uuidReq}).from("usersKey");
                getCrypto.map(result=>cryptoKey=result["keyCrypto"]);
                console.log(passwordReq)
                const password = aes256({key:cryptoKey,method:"dec",text:passwordReq})
                if(pass===password) {
                    const start = await knex.select("uuid","name","surname","avatar").where({email:uid,client:"okki"}).from("users");
                    if(start.length === 0) {
                        console.log("Not found");
                        res.sendStatus(404);
                    } else {
                        start.map(async(result)=>{
                            const {v4: uuidv4} = require('uuid');
                            const data = String(Date.now());
                            const clientId = data+"-"+uuidv4();
                            const AccessToken = generateAccessToken({uuid:result.uuid,clientId:clientId});
                            const refreshToken = generateRefreshToken({uuid:result.uuid,clientId:clientId});
                            const avatarUser = result.avatar;
                            const httpCheck = req.hostname==='localhost'?'http://':"https://";
                            const portCheck = req.hostname==='localhost'?':'+process.env.PORT:"";
                            const avatarResult = httpCheck+req.hostname+portCheck+avatarUser;
                            if (!(await knex.schema.hasTable(result.uuid+'_usersToken'))) {
                                await knex.schema.createTable(result.uuid+'_usersToken', function(table) {
                                    table.string('clientId').primary();
                                    table.text('getTime');
                                    table.text('clientInfo');
                                    table.text('accessToken');
                                    table.text('refreshToken');
                                });
                            }
                            const tokenStart = await knex(result.uuid+'_usersToken').insert({clientId:clientId,getTime:data,clientInfo:clientInfo,accessToken:AccessToken,refreshToken:refreshToken});
                            const tokenInsert = await knex('usersToken').insert({uuid:result.uuid,accessToken:AccessToken,refreshToken:refreshToken,clientId:clientId});
                            res.json({accessToken:aes.encrypt(AccessToken),name:aes.encrypt(aes256({key:cryptoKey,method:"dec",text:result.name})),surname:aes.encrypt(aes256({key:cryptoKey,method:"dec",text:result.surname})),avatar:aes.encrypt(avatarResult)});
                            console.log("Exist: "+uid);
                            console.log("New token to "+uid+" is: "+AccessToken);
                        });
                    }
                } else {
                    res.sendStatus(404);
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
            const start = await knex.select("email","uuid",'otp').where({email:uid,client:client}).from("users");
            if(start.length == 0) {
                res.sendStatus(404); // User not found
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
                    const upd = await knex("users").where({uuid:result.uuid}).update({otp:otp_key});
                });
                res.json({success:true});
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
            console.log(uid+" "+client)
            const start = await knex.select("name","surname","avatar","uuid","email").where({email:uid,client:client}).from("users");
            if(start.length === 0) {
                res.sendStatus(404);
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
                res.json({success:true,name:aes.encrypt(nameResult),surname:aes.encrypt(surnameResult),avatar:aes.encrypt(avatarResult),email:aes.encrypt(email)});
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
                res.json({otp:aes.encrypt(otp_key),success:true});
            } else {
                res.sendStatus(404);
            }
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/verify-email-otp - Mistake, mistake is ");
        console.log(e)
        return res.sendStatus(500);
    }
});



router.post('/reset-password-otp',async(req,res)=>{
    try {
        const otp = req.body.otp;
        const email = aes.decrypt(req.body.email);
        let start = await knex.select("uuid").where({email:email}).andWhere({otp:otp}).from('users');
        if(start.length===0) res.sendStatus(404);
        else res.json({success:true});
    } catch {
        console.log('\x1b[31m%s\x1b[0m',"/reset-password-otp - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
    }
});

router.post('/generate-token',async(req,res) => {
    try {
        const accessToken = aes.decrypt(req.body.token);
        if(accessToken!==undefined) {
            const refreshToken = await knex.select("refreshToken","uuid").where({accessToken:accessToken}).from("usersToken");
            const refreshTokens = await knex.select("refreshToken").from("usersToken");
            if(JSON.stringify(refreshToken)==="[]") return res.sendStatus(409);
            if(JSON.stringify(refreshTokens)==="[]") return res.sendStatus(409);
            let getRefreshToken = null;
            let uuid = null;
            let getRefreshTokens = [];
            let clientId = null;
            refreshToken.map((result)=>{getRefreshToken = result.refreshToken;uuid = result.uuid;});
            refreshTokens.map((result)=>getRefreshTokens.push(result.refreshToken));
            const getClientId = await knex.select("clientId").from(uuid+"_usersToken");
            getClientId.map((result)=>clientId=result.clientId);
            if (getRefreshToken == null) return res.sendStatus(409);
            if (!getRefreshTokens.includes(getRefreshToken)) return res.sendStatus(403);
            jwt.verify(getRefreshToken, process.env.REFRESH_TOKEN, async(err, user) => {
                if (err) return res.sendStatus(403);
                const accessTokenGeneration = generateAccessToken({ uuid:uuid,clientId:clientId });
                const upd = await knex("usersToken").where({uuid:uuid,accessToken:accessToken}).update({accessToken:accessTokenGeneration});
                const access = aes.encrypt(accessTokenGeneration);
                res.json({ accessToken: access });
            });
        }
    }
    catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/generate-token - Mistake, mistake is ");
        console.log(e);
        return res.sendStatus(500);
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
        const start = await knex.select("email").where({email:email,client:client}).from("users");
        if(start.length == 0) {
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
            const usersStart = await knex('users').insert({uuid:uuid,login:aes256({key:keyCrypto,method:"enc",text:loginUser}),email:email,password:aes256({key:keyCrypto,method:"enc",text:password}),name:aes256({key:keyCrypto,method:"enc",text:name}),surname:aes256({key:keyCrypto,method:"enc",text:surname}),data:data,avatar:"/images/unknown.webp",client:client});
            const cryptoStart = await knex('usersKey').insert({uuid:uuid,keyCrypto:keyCrypto});
            if (!(await knex.schema.hasTable(uuid+'_usersToken'))) {
                await knex.schema.createTable(uuid+'_usersToken', function(table) {
                    table.string('clientId').primary();
                    table.text('getTime');
                    table.text('clientInfo');
                    table.text('accessToken');
                    table.text('refreshToken');
                });
            }
            const tokenStart = await knex(uuid+'_usersToken').insert({clientId:clientId,getTime:data,clientInfo:clientInfo,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
            const tokenInsert = await knex('usersToken').insert({uuid:uuid,clientId:clientId,accessToken:accessTokenGeneration,refreshToken:refreshTokenGeneration});
            res.json({success:true,accessToken:aes.encrypt(accessTokenGeneration)})
            console.log('\x1b[32m%s\x1b[0m',"№"+newId+") Registered new user "+email);
        } else {
            res.json({email:true});
        }
    } catch(e) {
        console.log('\x1b[31m%s\x1b[0m',"/register-id - Mistake, mistake is ");
        console.log(e)
        return res.sendStatus(500);
    }
});


module.exports = router;
