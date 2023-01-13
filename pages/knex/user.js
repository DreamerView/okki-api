require('dotenv').config("../../.env");
const user = {
    client: 'mysql2',
    connection: {
      host : process.env.DATABASE_HOST,
      port : process.env.DATABASE_PORT,
      user : process.env.DATABASE_USER,
      password : process.env.DATABASE_PASSWORD,
      database : process.env.DATABASE_NAME_USERS,
      charset: "utf8"
    },
    pool: {
      min: 0,
      max: 5000
    }
};

module.exports = user;
