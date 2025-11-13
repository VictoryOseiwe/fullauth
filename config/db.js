import { Sequelize } from "sequelize";
import "dotenv/config";
import pg from "pg";

export const db = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: "postgres",
    dialectModule: pg,
    port: process.env.DB_PORT,
  }
);

// connect and test the database

async function testDBConnection() {
  try {
    await db.authenticate();
    console.log("Connection has been established successfully.");
  } catch (error) {
    console.error("Unable to connect to the database:", error);
  }
}

testDBConnection();
