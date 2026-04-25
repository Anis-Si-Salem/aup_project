"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { getMyLicense, type License, logout } from "@/lib/api";

export default function MyLicensePage() {
  const router = useRouter();
  const [license, setLicense] = useState<License | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const role = localStorage.getItem("aup_role");
    if (role !== "customer") {
      router.push("/customer-login");
      return;
    }
    getMyLicense()
      .then((lic) => setLicense(lic))
      .catch((err) => setError(err.message || "Failed to load license"))
      .finally(() => setLoading(false));
  }, [router]);

  function handleCopy() {
    if (!license) return;
    navigator.clipboard.writeText(JSON.stringify(license, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleDownload() {
    if (!license) return;
    const blob = new Blob([JSON.stringify(license, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `license_${license.fingerprint}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleLogout() {
    logout();
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black">
        <p className="text-sm text-zinc-500">Loading license...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
        <div className="w-full max-w-lg text-center">
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          <button
            onClick={() => router.push("/customer-login")}
            className="mt-4 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white dark:bg-zinc-100 dark:text-zinc-900"
          >
            Back to Login
          </button>
        </div>
      </div>
    );
  }

  if (!license) return null;

  const isExpired = new Date(license.expires_at) < new Date();

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-black px-4 py-8">
      <div className="mx-auto max-w-2xl">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">My License</h1>
            <p className="mt-1 text-sm text-zinc-500">Your signed license details</p>
          </div>
          <button
            onClick={handleLogout}
            className="rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-600 hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-400 dark:hover:bg-zinc-900"
          >
            Sign out
          </button>
        </div>

        <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
          <div className="grid grid-cols-2 gap-4 mb-6">
            <div>
              <p className="text-xs text-zinc-500">Status</p>
              <span className={`inline-block mt-1 rounded-full px-2 py-0.5 text-xs font-medium ${isExpired ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400" : "bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-400"}`}>
                {isExpired ? "Expired" : "Active"}
              </span>
            </div>
            <div>
              <p className="text-xs text-zinc-500">Fingerprint</p>
              <p className="mt-1 text-sm font-mono text-zinc-900 dark:text-zinc-100">{license.fingerprint}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-500">Max Users</p>
              <p className="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{license.max_users}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-500">License Key</p>
              <p className="mt-1 text-sm font-mono text-zinc-900 dark:text-zinc-100">{license.license_key}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-500">Issued</p>
              <p className="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{license.issued_at}</p>
            </div>
            <div>
              <p className="text-xs text-zinc-500">Expires</p>
              <p className="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{license.expires_at}</p>
            </div>
          </div>

          <div>
            <p className="text-xs text-zinc-500 mb-2">Signature</p>
            <pre className="rounded-lg bg-zinc-100 p-3 text-xs font-mono text-zinc-700 break-all dark:bg-zinc-800 dark:text-zinc-300">
              {license.signature}
            </pre>
          </div>
        </div>

        <div className="mt-4 flex gap-3">
          <button
            onClick={handleCopy}
            className="flex-1 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
          >
            {copied ? "Copied!" : "Copy JSON"}
          </button>
          <button
            onClick={handleDownload}
            className="flex-1 rounded-lg border border-zinc-200 px-4 py-2 text-sm font-medium text-zinc-700 transition hover:bg-zinc-100 dark:border-zinc-800 dark:text-zinc-300 dark:hover:bg-zinc-900"
          >
            Download JSON
          </button>
        </div>
      </div>
    </div>
  );
}