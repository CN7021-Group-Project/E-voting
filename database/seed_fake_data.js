/**********************************************************************
 * CLEAN + WORKING SEED GENERATOR
 * - Inserts Users → Elections → Candidates → Votes
 * - Weighted turnout distribution (low/medium/high)
 * - Prevents duplicate votes
 * - Live progress updates
 **********************************************************************/

import { faker } from "@faker-js/faker";
import mysql from "mysql2/promise";

/******** DB ********/
const DB = {
  host: "localhost",
  user: "root",
  password: "",
  database: "votesecure"
};

function hash() { return faker.string.alphanumeric(64); }

/*** turnout model ***/
function turnoutRate(){
  return faker.helpers.weightedArrayElement([
    {weight:45,value: faker.number.float({min:0.10,max:0.35})}, // Low
    {weight:35,value: faker.number.float({min:0.35,max:0.70})}, // Medium
    {weight:20,value: faker.number.float({min:0.70,max:0.95})}  // High
  ]);
}

/*** START ***/
(async()=>{

  const conn = await mysql.createConnection(DB);
  console.log("\n🔗 Connected");

  /******** RESET DB ********/
  console.log("🧹 Clearing Database...");
  await conn.execute("SET FOREIGN_KEY_CHECKS=0");
  await conn.execute("TRUNCATE users");
  await conn.execute("TRUNCATE elections");
  await conn.execute("TRUNCATE candidates");
  await conn.execute("TRUNCATE votes");
  await conn.execute("SET FOREIGN_KEY_CHECKS=1");

  /******** USERS ********/
  console.log("\n👤 Creating 1000 users...");
  for(let i=1;i<=1000;i++){
    await conn.execute(
      `INSERT INTO users(name,email,password_hash,role,blockchain_address) VALUES (?,?,?,?,?)`,
      [faker.person.fullName(),faker.internet.email(),"hashed","voter",hash()]
    );
  }
  console.log("✔ Users inserted: 1000");

  /******** ELECTIONS ********/
  console.log("\n🗳 Creating 1000 elections...");
  for(let i=1;i<=1000;i++){
    await conn.execute(
      `INSERT INTO elections(title,description,start_date,end_date,status,blockchain_hash,created_by)
       VALUES (?,?,?,?,?,?,?)`,
      [
        faker.company.name(),
        faker.lorem.sentence(),
        faker.date.past(),
        faker.date.future(),
        "completed",
        hash(),
        Math.floor(Math.random()*1000)+1   // valid FK user_id
      ]
    );
  }
  console.log("✔ Elections created: 1000");

  /******** CANDIDATES ********/
  console.log("\n👥 Assigning candidates...");
  const [allElections] = await conn.execute("SELECT id FROM elections");
  const electionIds = allElections.map(e=>e.id);

  let candidates = [];
  for(let id of electionIds){
    let num = faker.number.int({min:2,max:8});
    for(let i=0;i<num;i++){
      candidates.push([id,faker.person.fullName()]);
    }
  }
  await conn.query("INSERT INTO candidates(election_id,name) VALUES ?",[candidates]);
  console.log(`✔ Candidates inserted: ${candidates.length}`);

  /******** VOTES ********/
  console.log("\n🗳 Generating realistic turnout + LIVE progress...");

  let processed=0,totalVotes=0;

  for(let e of electionIds){

    const turnout = turnoutRate();
    const registered = 1000; // because we created 1000 voters
    const votesNeeded = Math.floor(turnout * registered);
    totalVotes += votesNeeded;

    let used = new Set();

    for(let i=0;i<votesNeeded;i++){
      let voter;
      do{ voter = faker.number.int({min:1,max:1000}); }
      while(used.has(voter));
      used.add(voter);

      const [cand] = await conn.execute(
        `SELECT id FROM candidates WHERE election_id=? ORDER BY RAND() LIMIT 1`,[e]
      );
      await conn.execute(
        `INSERT INTO votes(election_id,candidate_id,voter_id,blockchain_hash,vote_hash)
         VALUES (?,?,?,?,?)`,
        [e,cand[0].id,voter,hash(),hash()]
      );
    }

    processed++;
    process.stdout.write(`\r${processed}/1000 elections → total votes: ${totalVotes.toLocaleString()}`);
  }

  console.log("\n\n🎉 SEED COMPLETE!");
  console.log(`🔥 Total Votes Generated = ${totalVotes.toLocaleString()}`);

  process.exit();

})();
