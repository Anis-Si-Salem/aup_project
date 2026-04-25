import initSqlJs, { Database } from "sql.js";
import path from "path";
import fs from "fs";
import bcrypt from "bcrypt";

const DB_DIR = path.join(__dirname, "../../data");
const DB_PATH = path.join(DB_DIR, "aup.db");

let db: Database;

export function getDb(): Database {
  if (!db) {
    throw new Error("Database not initialized. Call initDb() first.");
  }
  return db;
}

export async function initDb(): Promise<Database> {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_key TEXT NOT NULL UNIQUE,
      fingerprint TEXT,
      signature TEXT NOT NULL,
      max_users INTEGER NOT NULL DEFAULT 1,
      issued_at TEXT NOT NULL,
      expires_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS customer_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      note TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      fingerprint TEXT NOT NULL,
      entries TEXT NOT NULL,
      uploaded_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      price_dzd INTEGER NOT NULL,
      max_users INTEGER NOT NULL DEFAULT 1,
      duration_days INTEGER NOT NULL,
      description TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  saveDb();

  // Seed default admin account if no users exist
  const userCheck = db.exec("SELECT COUNT(*) as cnt FROM users");
  const count = userCheck[0]?.values[0]?.[0] ?? 0;
  if (count === 0) {
    const hash = await bcrypt.hash("admin", 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", ["admin", hash]);
    saveDb();
    console.log("Seeded default admin account (username: admin, password: admin)");
  }

  return db;
}

export function saveDb(): void {
  if (!db) return;
  if (!fs.existsSync(DB_DIR)) {
    fs.mkdirSync(DB_DIR, { recursive: true });
  }
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}