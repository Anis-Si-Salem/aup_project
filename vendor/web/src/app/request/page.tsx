"use client";

import { useState } from "react";
import { submitLicenseRequest, lookupLicense, type License } from "@/lib/api";

export default function RequestPage() {
  const [step, setStep] = useState<"fingerprint" | "form" | "found" | "submitted">("fingerprint");
  const [fingerprint, setFingerprint] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [license, setLicense] = useState<License | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleFingerprintSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const lic = await lookupLicense(fingerprint.trim());
      if (lic) {
        setLicense(lic);
        setStep("found");
      } else {
        setStep("form");
      }
    } catch {
      setError("Error checking fingerprint. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRequestSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await submitLicenseRequest({ name, email, fingerprint, note });
      setStep("submitted");
    } catch {
      setError("Failed to submit request. Please try again.");
    } finally {
      setLoading(false);
    }
  }

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

  if (step === "found" && license) {
    const isExpired = new Date(license.expires_at) < new Date();
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
        <div className="w-full max-w-2xl">
          <div className="mb-6 text-center">
            <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
              <svg className="h-6 w-6 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <h2 className="mt-4 text-xl font-semibold text-zinc-900 dark:text-zinc-100">License Found</h2>
            <p className="mt-1 text-sm text-zinc-500">Your signed license is ready. Copy or download it below.</p>
          </div>

          <div className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <p className="text-xs text-zinc-500">Status</p>
                <span className={`inline-block mt-1 rounded-full px-2 py-0.5 text-xs font-medium ${isExpired ? "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400" : "bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-400"}`}>
                  {isExpired ? "Expired" : "Active"}
                </span>
              </div>
              <div>
                <p className="text-xs text-zinc-500">Fingerprint</p>
                <p className="mt-1 text-sm font-mono text-zinc-900 dark:text-zinc-100 truncate">{license.fingerprint}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500">Max Users</p>
                <p className="mt-1 text-sm text-zinc-900 dark:text-zinc-100">{license.max_users}</p>
              </div>
              <div>
                <p className="text-xs text-zinc-500">License Key</p>
                <p className="mt-1 text-sm font-mono text-zinc-900 dark:text-zinc-100 truncate">{license.license_key}</p>
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
              <p className="text-xs text-zinc-500 mb-1">Signature</p>
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

          <button
            onClick={() => { setStep("fingerprint"); setFingerprint(""); setLicense(null); }}
            className="mt-4 w-full text-center text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
          >
            Check another fingerprint
          </button>
        </div>
      </div>
    );
  }

  if (step === "submitted") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
        <div className="w-full max-w-sm text-center space-y-4">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-green-100 dark:bg-green-950">
            <svg className="h-6 w-6 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100">Request Submitted</h2>
          <p className="text-sm text-zinc-500">
            Your license request has been received. Come back here with your fingerprint once the vendor approves it.
          </p>
          <p className="text-xs text-zinc-400 font-mono break-all">{fingerprint}</p>
          <button
            onClick={() => { setStep("fingerprint"); setFingerprint(""); }}
            className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900"
          >
            Check again
          </button>
        </div>
      </div>
    );
  }

  if (step === "form") {
    return (
      <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
        <div className="w-full max-w-md">
          <div className="mb-8">
            <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">Request a License</h1>
            <p className="mt-1 text-sm text-zinc-500">No license found for this fingerprint. Fill in the form to request one.</p>
            <p className="mt-1 text-xs font-mono text-zinc-400">{fingerprint}</p>
          </div>

          <form
            onSubmit={handleRequestSubmit}
            className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 space-y-4"
          >
            {error && (
              <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">
                {error}
              </p>
            )}
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-xs text-zinc-500">Full Name</label>
                <input
                  type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="Jane Smith"
                  className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs text-zinc-500">Email</label>
                <input
                  type="email" value={email} onChange={(e) => setEmail(e.target.value)} required placeholder="jane@company.com"
                  className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
                />
              </div>
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Note (optional)</label>
              <textarea
                value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Organization name, intended use, etc."
                className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100 resize-none"
              />
            </div>
            <button
              type="submit" disabled={loading}
              className="w-full rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
            >
              {loading ? "Submitting..." : "Submit Request"}
            </button>
          </form>

          <button onClick={() => { setStep("fingerprint"); }} className="mt-4 w-full text-center text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200">
            ← Try a different fingerprint
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-zinc-50 dark:bg-black px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8">
          <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-100">Retrieve Your License</h1>
          <p className="mt-1 text-sm text-zinc-500">Enter your hardware fingerprint to check for an approved license or request a new one.</p>
        </div>

        <form
          onSubmit={handleFingerprintSubmit}
          className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 space-y-4"
        >
          {error && (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">
              {error}
            </p>
          )}
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Hardware Fingerprint</label>
            <input
              type="text" value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} required autoFocus
              placeholder="a1b2c3d4e5f6..."
              className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 font-mono text-xs text-zinc-900 focus:outline-none focus:ring-2 focus:ring-zinc-400 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
            />
            <p className="mt-1 text-xs text-zinc-400">
              Run <code className="rounded bg-zinc-100 px-1 dark:bg-zinc-800">./secure_installer</code> on your machine to obtain this.
            </p>
          </div>
          <button
            type="submit" disabled={loading}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300"
          >
            {loading ? "Checking..." : "Check Fingerprint"}
          </button>
        </form>

        <p className="mt-4 text-center text-xs text-zinc-400">
          Vendor?{" "}
          <a href="/login" className="underline hover:text-zinc-600 dark:hover:text-zinc-200">Sign in</a>
        </p>
      </div>
    </div>
  );
}