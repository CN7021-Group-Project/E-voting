const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");

async function main() {

    const conn = await mysql.createConnection({
        host: "localhost",
        user: "root",
        password: "",
        database: "votesecure"
    });

    console.log("\nFetching ML training data...");

    const [rows] = await conn.execute(`
        SELECT * FROM ml_turnout_features;
    `);

    const filePath = path.join(__dirname, "../prediction/ml_turnout_features.csv");

    console.log("📄 Writing CSV ➝ " + filePath);

    const header = Object.keys(rows[0]).join(",") + "\n";

    const csv = header + rows.map(row =>
        Object.values(row).join(",")
    ).join("\n");

    // <— creates file successfully
    fs.writeFileSync(filePath, csv); 

    console.log("\nCSV Export Complete!");
    console.log("👉 File saved at: prediction/ml_turnout_features.csv\n");

    process.exit();
}

main().catch(console.error);
