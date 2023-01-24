require('dotenv').config();
console.time('Knex connected in');
const user = {
    client: 'mysql2',
    connection: {
      host : process.env.DATABASE_HOST,
      port : process.env.DATABASE_PORT,
      user : process.env.DATABASE_USER,
      password : process.env.DATABASE_PASSWORD,
      database : process.env.DATABASE_NAME_USERS,
      multipleStatements: true
    },
    pool: { min: 0, max: 7 }
};
const knex = require('knex')(user);

knex.raw('SELECT VERSION()').then(()=>{
  console.log('\x1b[35m%s\x1b[0m','Knex connected to Database!')
});
console.timeEnd('Knex connected in');
module.exports = knex;
