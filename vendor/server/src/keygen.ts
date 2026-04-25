import crypto from "crypto";
import fs from "fs";
import path from "path";

const DATA_DIR = path.join(__dirname, "../../data");
const PRIVATE_KEY_PATH = path.join(DATA_DIR, "private.pem");
const PUBLIC_KEY_PATH = path.join(DATA_DIR, "public.pem");

let privateKey: string;
let publicKey: string;

export function getPrivateKey(): string {
  return privateKey;
}

export function getPublicKey(): string {
  return publicKey;
}

export function initKeys(): void {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    privateKey = fs.readFileSync(PRIVATE_KEY_PATH, "utf-8");
    publicKey = fs.readFileSync(PUBLIC_KEY_PATH, "utf-8");
    console.log("Loaded existing RSA key pair");
    return;
  }

  const { publicKey: pub, privateKey: priv } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  fs.writeFileSync(PRIVATE_KEY_PATH, priv, { mode: 0o600 });
  fs.writeFileSync(PUBLIC_KEY_PATH, pub);
  privateKey = priv;
  publicKey = pub;
  console.log("Generated new RSA key pair");
}