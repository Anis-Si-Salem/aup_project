import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { getDb, saveDb } from "../database";
import { JWT_SECRET } from "../middleware/auth";

const router = Router();

// POST /api/auth/login
router.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body;
  if (!username || !password) {
    res.status(400).json({ error: "username and password are required" });
    return;
  }
  try {
    const db = getDb();
    const result = db.exec("SELECT id, username, password FROM users WHERE username = ?", [username]);
    if (result.length === 0 || result[0].values.length === 0) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }
    const [id, uname, hash] = result[0].values[0] as [number, string, string];
    const match = await bcrypt.compare(password, hash);
    if (!match) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }
    const token = jwt.sign({ id, username: uname }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, username: uname });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/auth/register — vendor-only: seed a user (or protect with a seed secret)
router.post("/register", async (req: Request, res: Response) => {
  const { username, password, seed_secret } = req.body;
  if (seed_secret !== (process.env.SEED_SECRET || "aup-seed-secret")) {
    res.status(403).json({ error: "Forbidden" });
    return;
  }
  if (!username || !password) {
    res.status(400).json({ error: "username and password are required" });
    return;
  }
  try {
    const db = getDb();
    const hash = await bcrypt.hash(password, 10);
    db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash]);
    saveDb();
    res.status(201).json({ ok: true });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("UNIQUE")) {
      res.status(409).json({ error: "Username already exists" });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  }
});

// POST /api/auth/customer-login — fingerprint → returns customer JWT if license exists
router.post("/customer-login", (req: Request, res: Response) => {
  const { fingerprint } = req.body;
  if (!fingerprint) {
    res.status(400).json({ error: "fingerprint is required" });
    return;
  }
  try {
    const db = getDb();
    const result = db.exec(
      "SELECT id, license_key, fingerprint, signature, max_users, issued_at, expires_at FROM licenses WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
      [fingerprint]
    );
    if (result.length === 0 || result[0].values.length === 0) {
      res.status(404).json({ error: "No approved license found for this fingerprint" });
      return;
    }
    const token = jwt.sign({ role: "customer", fingerprint }, JWT_SECRET, { expiresIn: "1d" });
    res.json({ token, fingerprint });
  } catch (err) {
    console.error("Customer login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
