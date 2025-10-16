import mysql from 'mysql2/promise'; // <- use promise version

const msMain = {
  HOST: "116.203.172.166",
  USER: "root",
  PASSWORD: "Belectriq##$$%%##",
  DB: "embedorderdata",
  PORT: 3306
};

// Create pool (promise-based)
export const pool = mysql.createPool({
  host: msMain.HOST,
  user: msMain.USER,
  password: msMain.PASSWORD,
  database: msMain.DB,
  port: msMain.PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Test connection safely
(async () => {
  let conn;
  try {
    conn = await pool.getConnection();
    console.log('✅ Connected to MySQL database');
  } catch (err) {
    console.error('❌ Unable to connect to MySQL:', err.message);
    process.exit(1);
  } finally {
    if (conn) conn.release(); // release only if connection was obtained
  }
})();
