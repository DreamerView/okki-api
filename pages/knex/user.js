require('dotenv').config();
console.time('database connected in');
const user = {
    client: 'mysql2',
    connection: {
      host : process.env.DATABASE_HOST,
      port : process.env.DATABASE_PORT,
      user : process.env.DATABASE_USER,
      password : process.env.DATABASE_PASSWORD,
      database : process.env.DATABASE_NAME_USERS,
    },
    pool: { min: 0, max: 7 }
};
const knex = require('knex')(user);

knex.raw('SELECT VERSION()').then(()=>{
  console.log('connection to db successfully!')
});
console.timeEnd('database connected in');
module.exports = knex;
