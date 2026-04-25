import express from "express";
import cors from "cors";
import { initKeys } from "./keygen";
import { initDb } from "./database";
import licenseRoutes from "./routes/license";
import authRoutes from "./routes/auth";
import planRoutes from "./routes/plans";

const PORT = process.env.PORT || 3001;

async function main() {
  const app = express();

  app.use(cors());
  app.use(express.json());

  initKeys();
  await initDb();

  app.use("/api/auth", authRoutes);
  app.use("/api/license", licenseRoutes);
  app.use("/api/plans", planRoutes);

  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
