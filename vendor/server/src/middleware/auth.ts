import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export const JWT_SECRET = process.env.JWT_SECRET || "aup-vendor-secret-change-in-prod";

export interface AuthRequest extends Request {
  userId?: number;
  username?: string;
  role?: "admin" | "customer";
  fingerprint?: string;
}

export function requireAuth(req: AuthRequest, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as {
      id?: number;
      username?: string;
      role?: string;
      fingerprint?: string;
    };
    req.userId = payload.id;
    req.username = payload.username;
    req.role = (payload.role as "admin" | "customer") || "admin";
    req.fingerprint = payload.fingerprint;
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

export function requireAdmin(req: AuthRequest, res: Response, next: NextFunction): void {
  requireAuth(req, res, () => {
    if (req.role === "customer") {
      res.status(403).json({ error: "Admin access required" });
      return;
    }
    next();
  });
}
