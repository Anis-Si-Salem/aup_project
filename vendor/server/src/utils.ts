import crypto from "crypto";
import { getPrivateKey, getPublicKey } from "./keygen";

export function signWithPrivateKey(data: string): string {
  const signer = crypto.createSign("SHA256");
  signer.update(data);
  signer.end();
  return signer.sign(getPrivateKey(), "base64");
}

export function verifyWithPublicKey(data: string, signature: string): boolean {
  const verifier = crypto.createVerify("SHA256");
  verifier.update(data);
  verifier.end();
  return verifier.verify(getPublicKey(), signature, "base64");
}

export function encryptWithPublicKey(data: string): string {
  const buffer = Buffer.from(data, "utf-8");
  const encrypted = crypto.publicEncrypt(
    {
      key: getPublicKey(),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer
  );
  return encrypted.toString("base64");
}

export function decryptWithPrivateKey(encrypted: string): string {
  const buffer = Buffer.from(encrypted, "base64");
  const decrypted = crypto.privateDecrypt(
    {
      key: getPrivateKey(),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    buffer
  );
  return decrypted.toString("utf-8");
}