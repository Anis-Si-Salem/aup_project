"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { customerLogin } from "@/lib/api";

export default function CustomerLoginPage() {
  const router = useRouter();
  const [fingerprint, setFingerprint] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const { token, fingerprint: fp } = await customerLogin(fingerprint.trim());
      localStorage.setItem("aup_token", token);
      localStorage.setItem("aup_role", "customer");
      localStorage.setItem("aup_fingerprint", fp);
      router.push("/my-license");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">Customer Portal</h1>
          <p className="mt-1 text-sm text-zinc-500">Enter your device fingerprint to retrieve your license</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 space-y-4"
        >
          {error && (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Device Fingerprint</label>
            <input
              type="text"
              value={fingerprint}
              onChange={(e) => setFingerprint(e.target.value)}
              required
              autoFocus
              placeholder="e.g. a1b2c3d4e5f6..."
              className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 font-mono focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
          >
            {loading ? "Verifying..." : "Retrieve License"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-zinc-400">
          Need a license first?{" "}
          <a href="/request" className="underline hover:text-zinc-600 dark:hover:text-zinc-200">
            Request one
          </a>
        </p>
      </div>
    </div>
  );
}