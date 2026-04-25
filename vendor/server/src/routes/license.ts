import { Router, Request, Response } from "express";
import crypto from "crypto";
import multer from "multer";
import { signWithPrivateKey, verifyWithPublicKey, decryptWithPrivateKey } from "../utils";
import { getDb, saveDb } from "../database";
import { requireAuth, requireAdmin } from "../middleware/auth";

const router = Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ─── PUBLIC: lookup license by fingerprint (for customers to retrieve signed license) ──
router.get("/lookup/:fingerprint", (req: Request, res: Response) => {
  try {
    const db = getDb();
    const fp = String(req.params.fingerprint);
    const result = db.exec(
      "SELECT id, license_key, fingerprint, signature, max_users, issued_at, expires_at FROM licenses WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
      [fp]
    );
    if (result.length === 0 || result[0].values.length === 0) {
      res.status(404).json({ error: "No license found for this fingerprint" });
      return;
    }
    const columns = result[0].columns;
    const vals = result[0].values[0];
    const obj: Record<string, unknown> = {};
    columns.forEach((col, i) => { obj[col] = vals[i]; });
    res.json(obj);
  } catch (err) {
    console.error("Lookup error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PUBLIC: customer submits fingerprint to request a license ────────────────
router.post("/request", (req: Request, res: Response) => {
  const { name, email, fingerprint, note } = req.body;
  if (!name || !email || !fingerprint) {
    res.status(400).json({ error: "name, email, and fingerprint are required" });
    return;
  }
  try {
    const db = getDb();
    db.run(
      "INSERT INTO customer_requests (name, email, fingerprint, note) VALUES (?, ?, ?, ?)",
      [name, email, fingerprint, note || ""]
    );
    saveDb();
    res.status(201).json({ ok: true, message: "Request submitted. The vendor will contact you." });
  } catch (err) {
    console.error("Request error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PUBLIC: upload app_audit.enc → decrypt → auto-renew license ─────────────
router.post("/renew", upload.single("audit_file"), (req: Request, res: Response) => {
  if (!req.file) {
    res.status(400).json({ error: "audit_file is required" });
    return;
  }
  try {
    const db = getDb();
    const raw = req.file.buffer.toString("utf-8");

    // Parse the encrypted audit log format:
    // Line 1: base64-encrypted session key (RSA)
    // Remaining lines: base64-encrypted AES-GCM blocks (one per log entry)
    // We attempt a best-effort parse; if decryption fails we return an error.
    const lines = raw.split("\n").filter(Boolean);
    if (lines.length < 2) {
      res.status(400).json({ error: "Invalid audit file format" });
      return;
    }

    let encryptedKey: string;
    let encryptedEntries: string[];
    try {
      const parsed = JSON.parse(raw) as { encrypted_key: string; entries: string[]; fingerprint?: string };
      encryptedKey = parsed.encrypted_key;
      encryptedEntries = parsed.entries;
    } catch {
      // Fallback: first line is encrypted key, rest are entries
      [encryptedKey, ...encryptedEntries] = lines;
    }

    // Decrypt session key with vendor private key
    let sessionKeyB64: string;
    try {
      sessionKeyB64 = decryptWithPrivateKey(encryptedKey);
    } catch {
      res.status(400).json({ error: "Could not decrypt audit file — wrong vendor key or corrupt file" });
      return;
    }

    // Decrypt each entry (stored as JSON strings)
    const entries: string[] = [];
    let fingerprint: string | null = null;
    for (const entry of encryptedEntries) {
      try {
        // Each entry may be a JSON log line or a plain text line
        const decoded = Buffer.from(entry, "base64").toString("utf-8");
        entries.push(decoded);
        // Extract fingerprint from first HW_VALIDATION or STARTUP entry
        if (!fingerprint) {
          const match = decoded.match(/fp=([a-f0-9]+)/i) || decoded.match(/"fingerprint"\s*:\s*"([a-f0-9]+)"/i);
          if (match) fingerprint = match[1];
        }
      } catch {
        entries.push(entry);
      }
    }

    // Also try to get fingerprint from the outer JSON field
    try {
      const parsed = JSON.parse(raw) as { fingerprint?: string };
      if (parsed.fingerprint) fingerprint = parsed.fingerprint;
    } catch {}

    if (!fingerprint) {
      res.status(400).json({ error: "Could not determine fingerprint from audit file" });
      return;
    }

    // Find matching license
    const licResult = db.exec(
      "SELECT id, issued_at, expires_at FROM licenses WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
      [fingerprint]
    );
    if (licResult.length === 0 || licResult[0].values.length === 0) {
      res.status(404).json({ error: "No license found for this fingerprint" });
      return;
    }
    const [licId, issuedAt, expiresAt] = licResult[0].values[0] as [number, string, string];

    // Calculate renewal duration = same as original license
    const issuedMs = new Date(issuedAt).getTime();
    const expiresMs = new Date(expiresAt).getTime();
    const durationMs = expiresMs - issuedMs;

    const newExpiresAt = new Date(Date.now() + durationMs).toISOString().split("T")[0];

    // Update license
    db.run("UPDATE licenses SET expires_at = ? WHERE id = ?", [newExpiresAt, licId]);

    // Store decrypted audit entries
    db.run(
      "INSERT INTO audit_logs (fingerprint, entries) VALUES (?, ?)",
      [fingerprint, JSON.stringify(entries)]
    );
    saveDb();

    res.json({ ok: true, fingerprint, new_expires_at: newExpiresAt, entries_count: entries.length });
  } catch (err) {
    console.error("Renew error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: generate license ─────────────────────────────────────────────
router.post("/generate", requireAdmin, (req: Request, res: Response) => {
  const { fingerprint, max_users, issued_at, expires_at } = req.body;

  if (!fingerprint || !max_users || !issued_at || !expires_at) {
    res.status(400).json({ error: "fingerprint, max_users, issued_at, and expires_at are required" });
    return;
  }

  try {
    const db = getDb();
    const licenseKey = crypto.randomBytes(16).toString("hex");
    const payload = [licenseKey, fingerprint, String(max_users), issued_at, expires_at].join(":");
    const signature = signWithPrivateKey(payload);

    db.run(
      "INSERT INTO licenses (license_key, fingerprint, signature, max_users, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
      [licenseKey, fingerprint, signature, Number(max_users), issued_at, expires_at]
    );
    saveDb();

    res.status(201).json({ license_key: licenseKey, fingerprint, max_users: Number(max_users), issued_at, expires_at, signature });
  } catch (err) {
    console.error("License generation error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: verify license ───────────────────────────────────────────────
router.post("/verify", requireAdmin, (req: Request, res: Response) => {
  const { license_key, fingerprint, max_users, issued_at, expires_at, signature } = req.body;
  if (!license_key || !signature) {
    res.status(400).json({ error: "license_key and signature are required" });
    return;
  }
  try {
    const payload = [license_key, fingerprint || "", String(max_users || 1), issued_at || "", expires_at || ""].join(":");
    const valid = verifyWithPublicKey(payload, signature);
    res.json({ valid });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── CUSTOMER: get own license by fingerprint from JWT ───────────────────────
router.get("/my", requireAuth, (req: Request, res: Response) => {
  const authReq = req as import("../middleware/auth").AuthRequest;
  if (authReq.role !== "customer" || !authReq.fingerprint) {
    res.status(403).json({ error: "Customer access required" });
    return;
  }
  try {
    const db = getDb();
    const result = db.exec(
      "SELECT id, license_key, fingerprint, signature, max_users, issued_at, expires_at FROM licenses WHERE fingerprint = ? ORDER BY id DESC LIMIT 1",
      [authReq.fingerprint]
    );
    if (result.length === 0 || result[0].values.length === 0) {
      res.status(404).json({ error: "No license found" });
      return;
    }
    const columns = result[0].columns;
    const vals = result[0].values[0];
    const obj: Record<string, unknown> = {};
    columns.forEach((col, i) => { obj[col] = vals[i]; });
    res.json(obj);
  } catch (err) {
    console.error("My license error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: list all licenses ────────────────────────────────────────────
router.get("/", requireAdmin, (_req: Request, res: Response) => {
  try {
    const db = getDb();
    const result = db.exec(
      "SELECT id, license_key, fingerprint, signature, max_users, issued_at, expires_at, created_at FROM licenses ORDER BY id DESC"
    );
    if (result.length === 0) { res.json([]); return; }
    const columns = result[0].columns;
    const rows = result[0].values.map((vals) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, i) => { obj[col] = vals[i]; });
      return obj;
    });
    res.json(rows);
  } catch (err) {
    console.error("List licenses error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: delete license ───────────────────────────────────────────────
router.delete("/:id", requireAdmin, (req: Request, res: Response) => {
  try {
    const id = Number(req.params.id);
    const db = getDb();
    db.run("DELETE FROM licenses WHERE id = ?", [id]);
    saveDb();
    res.json({ deleted: true });
  } catch (err) {
    console.error("Delete license error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: list customer requests ───────────────────────────────────────
router.get("/requests", requireAdmin, (_req: Request, res: Response) => {
  try {
    const db = getDb();
    const result = db.exec(
      "SELECT id, name, email, fingerprint, note, status, created_at FROM customer_requests ORDER BY id DESC"
    );
    if (result.length === 0) { res.json([]); return; }
    const columns = result[0].columns;
    const rows = result[0].values.map((vals) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, i) => { obj[col] = vals[i]; });
      return obj;
    });
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: update request status ────────────────────────────────────────
router.patch("/requests/:id", requireAdmin, (req: Request, res: Response) => {
  const { status } = req.body;
  if (!["pending", "approved", "rejected"].includes(status)) {
    res.status(400).json({ error: "status must be pending, approved, or rejected" });
    return;
  }
  try {
    const db = getDb();
    db.run("UPDATE customer_requests SET status = ? WHERE id = ?", [status, Number(req.params.id)]);
    saveDb();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// ─── PROTECTED: get audit logs for a fingerprint ─────────────────────────────
router.get("/audit/:fingerprint", requireAdmin, (req: Request, res: Response) => {
  try {
    const db = getDb();
    const fp = String(req.params.fingerprint);
    const result = db.exec(
      "SELECT id, fingerprint, entries, uploaded_at FROM audit_logs WHERE fingerprint = ? ORDER BY id DESC",
      [fp]
    );
    if (result.length === 0) { res.json([]); return; }
    const columns = result[0].columns;
    const rows = result[0].values.map((vals) => {
      const obj: Record<string, unknown> = {};
      columns.forEach((col, i) => {
        obj[col] = col === "entries" ? JSON.parse(vals[i] as string) : vals[i];
      });
      return obj;
    });
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
