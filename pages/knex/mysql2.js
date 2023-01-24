require('dotenv').config();
console.time("MySQL2 connected in");
const mysql = require('mysql2');

const connection = mysql.createPool({
    debug    :  false,
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_NAME_USERS,
    multipleStatements: true,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

connection.getConnection((err) => {
    if (err) {
      console.log("MySQL2 database Connection Failed !!!", err);
    } else {
      console.log('\x1b[34m%s\x1b[0m',"MySQL2 connected to Database!");
    }
});

console.timeEnd("MySQL2 connected in");

module.exports = connection;