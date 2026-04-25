import { Router, Request, Response } from "express";
import { getDb, saveDb } from "../database";
import { requireAdmin } from "../middleware/auth";

const router = Router();

function rowsToJson(result: { columns: string[]; values: unknown[][] }[]): Record<string, unknown>[] {
  if (result.length === 0) return [];
  const columns = result[0].columns;
  return result[0].values.map((vals) => {
    const obj: Record<string, unknown> = {};
    columns.forEach((col, i) => { obj[col] = vals[i]; });
    return obj;
  });
}

router.get("/", requireAdmin, (_req: Request, res: Response) => {
  try {
    const db = getDb();
    const result = db.exec("SELECT id, name, price_dzd, max_users, duration_days, description, created_at FROM plans ORDER BY id");
    res.json(rowsToJson(result));
  } catch (err) {
    console.error("List plans error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/", requireAdmin, (req: Request, res: Response) => {
  const { name, price_dzd, max_users, duration_days, description } = req.body;
  if (!name || price_dzd == null || !duration_days) {
    res.status(400).json({ error: "name, price_dzd, and duration_days are required" });
    return;
  }
  try {
    const db = getDb();
    db.run(
      "INSERT INTO plans (name, price_dzd, max_users, duration_days, description) VALUES (?, ?, ?, ?, ?)",
      [name, Number(price_dzd), Number(max_users) || 1, Number(duration_days), description || ""]
    );
    saveDb();
    const result = db.exec("SELECT id, name, price_dzd, max_users, duration_days, description, created_at FROM plans ORDER BY id DESC LIMIT 1");
    res.status(201).json(rowsToJson(result)[0]);
  } catch (err) {
    console.error("Create plan error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.patch("/:id", requireAdmin, (req: Request, res: Response) => {
  const { name, price_dzd, max_users, duration_days, description } = req.body;
  try {
    const db = getDb();
    const id = Number(req.params.id);
    const existing = db.exec("SELECT id FROM plans WHERE id = ?", [id]);
    if (existing.length === 0 || existing[0].values.length === 0) {
      res.status(404).json({ error: "Plan not found" });
      return;
    }
    db.run(
      "UPDATE plans SET name = ?, price_dzd = ?, max_users = ?, duration_days = ?, description = ? WHERE id = ?",
      [name, Number(price_dzd), Number(max_users) || 1, Number(duration_days), description || "", id]
    );
    saveDb();
    const result = db.exec("SELECT id, name, price_dzd, max_users, duration_days, description, created_at FROM plans WHERE id = ?", [id]);
    res.json(rowsToJson(result)[0]);
  } catch (err) {
    console.error("Update plan error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.delete("/:id", requireAdmin, (req: Request, res: Response) => {
  try {
    const db = getDb();
    db.run("DELETE FROM plans WHERE id = ?", [Number(req.params.id)]);
    saveDb();
    res.json({ deleted: true });
  } catch (err) {
    console.error("Delete plan error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;