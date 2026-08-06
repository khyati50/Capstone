/**
 * MySQL Connection Pool Setup using mysql2/promise
 */

const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'capstone_user',
  password: process.env.DB_PASSWORD || 'CapstonePassword123!',
  database: process.env.DB_NAME || 'capstone_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool;
