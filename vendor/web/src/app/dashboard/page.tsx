"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  generateLicense,
  listLicenses,
  deleteLicense,
  listRequests,
  updateRequestStatus,
  getAuditLogs,
  listPlans,
  createPlan,
  deletePlan,
  logout,
  License,
  CustomerRequest,
  AuditLog,
  Plan,
} from "@/lib/api";

type Tab = "requests" | "licenses" | "plans";

// ─── Logs Modal ───────────────────────────────────────────────────────────────
function LogsModal({ fingerprint, onClose }: { fingerprint: string; onClose: () => void }) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getAuditLogs(fingerprint)
      .then(setLogs)
      .catch(() => setError("Failed to load logs"))
      .finally(() => setLoading(false));
  }, [fingerprint]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-zinc-200 bg-white shadow-xl dark:border-zinc-800 dark:bg-zinc-900 flex flex-col max-h-[80vh]">
        <div className="flex items-center justify-between border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
          <div>
            <h2 className="text-base font-semibold text-zinc-900 dark:text-zinc-100">Audit Logs</h2>
            <p className="mt-0.5 font-mono text-xs text-zinc-400 break-all">{fingerprint}</p>
          </div>
          <button onClick={onClose} className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800 dark:hover:text-zinc-200">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-6">
          {loading && <p className="text-sm text-zinc-400">Loading...</p>}
          {error && <p className="text-sm text-red-500">{error}</p>}
          {!loading && !error && logs.length === 0 && <p className="text-sm text-zinc-400">No audit logs found.</p>}
          {logs.map((log) => (
            <div key={log.id} className="mb-6">
              <p className="mb-2 text-xs text-zinc-400">Uploaded {new Date(log.uploaded_at).toLocaleString()}</p>
              <div className="rounded-lg border border-zinc-200 bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800 overflow-hidden">
                {log.entries.map((entry, i) => (
                  <div key={i} className="border-b border-zinc-200 px-4 py-2 font-mono text-xs text-zinc-700 last:border-0 dark:border-zinc-700 dark:text-zinc-300">
                    {entry}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Generate Modal ───────────────────────────────────────────────────────────
function GenerateModal({
  prefill,
  requestId,
  plans,
  onClose,
  onDone,
}: {
  prefill?: Partial<{ fingerprint: string; name: string; email: string }>;
  requestId?: number;
  plans: Plan[];
  onClose: () => void;
  onDone: () => void;
}) {
  const [fingerprint, setFingerprint] = useState(prefill?.fingerprint || "");
  const [maxUsers, setMaxUsers] = useState(1);
  const [issuedAt, setIssuedAt] = useState(new Date().toISOString().split("T")[0]);
  const [expiresAt, setExpiresAt] = useState("");
  const [selectedPlanId, setSelectedPlanId] = useState<number | "">("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  function handlePlanChange(id: number | "") {
    setSelectedPlanId(id);
    if (id === "") return;
    const plan = plans.find((p) => p.id === id);
    if (!plan) return;
    setMaxUsers(plan.max_users);
    const issued = new Date(issuedAt);
    const expires = new Date(issued);
    expires.setDate(expires.getDate() + plan.duration_days);
    setExpiresAt(expires.toISOString().split("T")[0]);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await generateLicense({ fingerprint, max_users: maxUsers, issued_at: issuedAt, expires_at: expiresAt });
      if (requestId) {
        await updateRequestStatus(requestId, "approved");
      }
      onDone();
    } catch {
      setError("Failed to generate license");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-zinc-200 bg-white shadow-xl dark:border-zinc-800 dark:bg-zinc-900">
        <div className="flex items-center justify-between border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-zinc-100">Generate License</h2>
          <button onClick={onClose} className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800 dark:hover:text-zinc-200">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {prefill?.name && (
            <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-2 text-sm text-blue-700 dark:border-blue-800 dark:bg-blue-950 dark:text-blue-300">
              Approving request from <strong>{prefill.name}</strong> ({prefill.email})
            </div>
          )}
          {error && (
            <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">{error}</p>
          )}
          {plans.length > 0 && (
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Plan (optional — auto-fills fields)</label>
              <select
                value={selectedPlanId}
                onChange={(e) => handlePlanChange(e.target.value ? Number(e.target.value) : "")}
                className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
              >
                <option value="">No plan — manual entry</option>
                {plans.map((p) => (
                  <option key={p.id} value={p.id}>{p.name} — {p.price_dzd.toLocaleString()} DZD · {p.max_users} users · {p.duration_days}d</option>
                ))}
              </select>
            </div>
          )}
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Fingerprint</label>
            <input type="text" value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 font-mono text-xs text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Max Users</label>
              <input type="number" value={maxUsers} min={1} onChange={(e) => setMaxUsers(Number(e.target.value))} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Issued At</label>
              <input type="date" value={issuedAt} onChange={(e) => setIssuedAt(e.target.value)} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Expires At</label>
              <input type="date" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="rounded-lg border border-zinc-300 px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
            <button type="submit" disabled={loading} className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300">
              {loading ? "Generating..." : "Generate"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Status badge ─────────────────────────────────────────────────────────────
function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    pending: "bg-yellow-100 text-yellow-700 dark:bg-yellow-950 dark:text-yellow-400",
    approved: "bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-400",
    rejected: "bg-red-100 text-red-600 dark:bg-red-950 dark:text-red-400",
    active: "bg-green-100 text-green-700 dark:bg-green-950 dark:text-green-400",
    expired: "bg-red-100 text-red-600 dark:bg-red-950 dark:text-red-400",
    expiring: "bg-orange-100 text-orange-700 dark:bg-orange-950 dark:text-orange-400",
  };
  return (
    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium capitalize ${colors[status] || colors.pending}`}>{status}</span>
  );
}

function licenseStatus(expiresAt: string): "active" | "expired" | "expiring" {
  const now = Date.now();
  const exp = new Date(expiresAt).getTime();
  if (exp < now) return "expired";
  if (exp - now < 30 * 24 * 60 * 60 * 1000) return "expiring";
  return "active";
}

// ─── Create/Edit Plan Modal ───────────────────────────────────────────────────
function PlanModal({ onClose, onDone, edit }: { onClose: () => void; onDone: () => void; edit?: Plan }) {
  const [name, setName] = useState(edit?.name || "");
  const [priceDzd, setPriceDzd] = useState(edit?.price_dzd ?? 1000000);
  const [maxUsers, setMaxUsers] = useState(edit?.max_users ?? 1);
  const [durationDays, setDurationDays] = useState(edit?.duration_days ?? 365);
  const [description, setDescription] = useState(edit?.description || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await createPlan({ name, price_dzd: priceDzd, max_users: maxUsers, duration_days: durationDays, description });
      onDone();
    } catch {
      setError("Failed to save plan");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-lg rounded-2xl border border-zinc-200 bg-white shadow-xl dark:border-zinc-800 dark:bg-zinc-900">
        <div className="flex items-center justify-between border-b border-zinc-200 px-6 py-4 dark:border-zinc-800">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-zinc-100">{edit ? "Edit Plan" : "New Plan"}</h2>
          <button onClick={onClose} className="rounded-lg p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 dark:hover:bg-zinc-800 dark:hover:text-zinc-200">
            <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">{error}</p>}
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Plan Name</label>
            <input type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="e.g. Standard, Professional" className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Price (DZD)</label>
              <input type="number" value={priceDzd} min={0} onChange={(e) => setPriceDzd(Number(e.target.value))} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Max Users</label>
              <input type="number" value={maxUsers} min={1} onChange={(e) => setMaxUsers(Number(e.target.value))} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
            <div>
              <label className="mb-1 block text-xs text-zinc-500">Duration (days)</label>
              <input type="number" value={durationDays} min={1} onChange={(e) => setDurationDays(Number(e.target.value))} required className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
            </div>
          </div>
          <div>
            <label className="mb-1 block text-xs text-zinc-500">Description (optional)</label>
            <input type="text" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Brief description of the plan" className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm text-zinc-900 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100" />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="rounded-lg border border-zinc-300 px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-300 dark:hover:bg-zinc-800">Cancel</button>
            <button type="submit" disabled={loading} className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-700 disabled:opacity-50 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300">
              {loading ? "Saving..." : edit ? "Update Plan" : "Create Plan"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const router = useRouter();
  const [tab, setTab] = useState<Tab>("requests");
  const [username, setUsername] = useState("");

  const [licenses, setLicenses] = useState<License[]>([]);
  const [requests, setRequests] = useState<CustomerRequest[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState<number | null>(null);

  const [logsFor, setLogsFor] = useState<string | null>(null);
  const [generateFor, setGenerateFor] = useState<Partial<{ fingerprint: string; name: string; email: string }> | null>(null);
  const [generateForReqId, setGenerateForReqId] = useState<number | undefined>(undefined);
  const [showPlanModal, setShowPlanModal] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("aup_token");
    if (!token) { router.replace("/login"); return; }
    const uname = localStorage.getItem("aup_username") || "vendor";
    setUsername(uname);
    fetchAll();
  }, []);

  async function fetchAll() {
    try {
      const [lics, reqs, plns] = await Promise.all([listLicenses(), listRequests(), listPlans()]);
      setLicenses(lics);
      setRequests(reqs);
      setPlans(plns);
    } catch {
      setError("Failed to load data");
    }
  }

  async function handleDelete(id: number) {
    try {
      await deleteLicense(id);
      setLicenses((prev) => prev.filter((l) => l.id !== id));
    } catch {
      setError("Failed to delete license");
    }
  }

  async function handleApprove(req: CustomerRequest) {
    setGenerateForReqId(req.id);
    setGenerateFor({ fingerprint: req.fingerprint, name: req.name, email: req.email });
  }

  async function handleReject(id: number) {
    try {
      await updateRequestStatus(id, "rejected");
      setRequests((prev) => prev.map((r) => (r.id === id ? { ...r, status: "rejected" } : r)));
    } catch {
      setError("Failed to update request");
    }
  }

  async function handleDeletePlan(id: number) {
    try {
      await deletePlan(id);
      setPlans((prev) => prev.filter((p) => p.id !== id));
    } catch {
      setError("Failed to delete plan");
    }
  }

  function copyLicense(lic: License) {
    const text = JSON.stringify({ license_key: lic.license_key, fingerprint: lic.fingerprint, max_users: lic.max_users, issued_at: lic.issued_at, expires_at: lic.expires_at, signature: lic.signature }, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(lic.id);
    setTimeout(() => setCopied(null), 2000);
  }

  const pendingCount = requests.filter((r) => r.status === "pending").length;

  const tabLabels: Record<Tab, string> = { requests: "License Requests", licenses: "Active Licenses", plans: "Business Model" };

  return (
    <>
      {logsFor && <LogsModal fingerprint={logsFor} onClose={() => setLogsFor(null)} />}
      {generateFor !== null && (
        <GenerateModal
          prefill={generateFor}
          requestId={generateForReqId}
          plans={plans}
          onClose={() => { setGenerateFor(null); setGenerateForReqId(undefined); }}
          onDone={async () => { setGenerateFor(null); setGenerateForReqId(undefined); await fetchAll(); }}
        />
      )}
      {showPlanModal && <PlanModal onClose={() => setShowPlanModal(false)} onDone={async () => { setShowPlanModal(false); await fetchAll(); }} />}

      <div className="min-h-screen bg-zinc-50 dark:bg-black">
        <header className="border-b border-zinc-200 bg-white dark:border-zinc-800 dark:bg-zinc-900">
          <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
            <span className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">Vendor Portal</span>
            <div className="flex items-center gap-4">
              <span className="text-xs text-zinc-500">{username}</span>
              <button onClick={logout} className="rounded-lg border border-zinc-300 px-3 py-1 text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-700 dark:text-zinc-400 dark:hover:bg-zinc-800">Sign out</button>
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-5xl px-6 py-8 space-y-6">
          {error && <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-600 dark:border-red-900 dark:bg-red-950 dark:text-red-400">{error}</p>}

          <div className="flex items-center gap-1 border-b border-zinc-200 dark:border-zinc-800">
            {(["requests", "licenses", "plans"] as Tab[]).map((t) => (
              <button key={t} onClick={() => setTab(t)} className={`relative px-4 py-2 text-sm font-medium transition-colors ${tab === t ? "text-zinc-900 dark:text-zinc-100" : "text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"}`}>
                {tabLabels[t]}
                {tab === t && <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-zinc-900 dark:bg-zinc-100 rounded-full" />}
                {t === "requests" && pendingCount > 0 && <span className="ml-1.5 inline-flex h-4 w-4 items-center justify-center rounded-full bg-orange-500 text-[10px] font-medium text-white">{pendingCount}</span>}
              </button>
            ))}
            <div className="ml-auto">
              <button onClick={() => setGenerateFor({})} className="rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300">+ New License</button>
            </div>
          </div>

          {/* ── Tab: Requests ── */}
          {tab === "requests" && (
            <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-zinc-200 text-xs text-zinc-500 dark:border-zinc-700">
                    <tr>
                      <th className="px-4 py-3 font-medium">Name</th>
                      <th className="px-4 py-3 font-medium">Email</th>
                      <th className="px-4 py-3 font-medium">Fingerprint</th>
                      <th className="px-4 py-3 font-medium">Note</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium">Submitted</th>
                      <th className="px-4 py-3 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                    {requests.length === 0 ? (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-400">No requests yet</td></tr>
                    ) : requests.map((req) => (
                      <tr key={req.id} className="text-zinc-700 dark:text-zinc-300">
                        <td className="px-4 py-3 font-medium">{req.name}</td>
                        <td className="px-4 py-3 text-xs">{req.email}</td>
                        <td className="px-4 py-3 font-mono text-xs max-w-[140px] truncate">{req.fingerprint}</td>
                        <td className="px-4 py-3 text-xs text-zinc-500 max-w-[160px] truncate">{req.note || "—"}</td>
                        <td className="px-4 py-3"><StatusBadge status={req.status} /></td>
                        <td className="px-4 py-3 text-xs">{new Date(req.created_at).toLocaleDateString()}</td>
                        <td className="px-4 py-3">
                          {req.status === "pending" && (
                            <div className="flex gap-2">
                              <button onClick={() => handleApprove(req)} className="rounded border border-green-300 px-2 py-1 text-xs text-green-700 hover:bg-green-50 dark:border-green-800 dark:text-green-400 dark:hover:bg-green-950">Approve</button>
                              <button onClick={() => handleReject(req.id)} className="rounded border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">Reject</button>
                            </div>
                          )}
                          {req.status !== "pending" && <span className="text-xs text-zinc-400 capitalize">{req.status}</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Tab: Licenses ── */}
          {tab === "licenses" && (
            <div className="rounded-2xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-zinc-200 text-xs text-zinc-500 dark:border-zinc-700">
                    <tr>
                      <th className="px-4 py-3 font-medium">Key</th>
                      <th className="px-4 py-3 font-medium">Fingerprint</th>
                      <th className="px-4 py-3 font-medium">Users</th>
                      <th className="px-4 py-3 font-medium">Issued</th>
                      <th className="px-4 py-3 font-medium">Expires</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
                    {licenses.length === 0 ? (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-zinc-400">No licenses yet</td></tr>
                    ) : licenses.map((lic) => {
                      const status = licenseStatus(lic.expires_at);
                      return (
                        <tr key={lic.id} className="text-zinc-700 dark:text-zinc-300">
                          <td className="px-4 py-3 font-mono text-xs">{lic.license_key.slice(0, 12)}…</td>
                          <td className="px-4 py-3 font-mono text-xs max-w-[140px] truncate">{lic.fingerprint}</td>
                          <td className="px-4 py-3 text-xs">{lic.max_users}</td>
                          <td className="px-4 py-3 text-xs">{new Date(lic.issued_at).toLocaleDateString()}</td>
                          <td className="px-4 py-3 text-xs">{new Date(lic.expires_at).toLocaleDateString()}</td>
                          <td className="px-4 py-3"><StatusBadge status={status} /></td>
                          <td className="px-4 py-3">
                            <div className="flex gap-2">
                              <button onClick={() => copyLicense(lic)} className="rounded border border-zinc-300 px-2 py-1 text-xs dark:border-zinc-600 dark:text-zinc-300">{copied === lic.id ? "Copied!" : "Copy"}</button>
                              <button onClick={() => setLogsFor(lic.fingerprint)} className="rounded border border-zinc-300 px-2 py-1 text-xs text-zinc-600 hover:bg-zinc-50 dark:border-zinc-600 dark:text-zinc-300 dark:hover:bg-zinc-800">Logs</button>
                              <button onClick={() => handleDelete(lic.id)} className="rounded border border-red-300 px-2 py-1 text-xs text-red-600 dark:border-red-800 dark:text-red-400">Delete</button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Tab: Plans (Business Model) ── */}
          {tab === "plans" && (
            <div className="space-y-4">
              <div className="flex justify-end">
                <button onClick={() => setShowPlanModal(true)} className="rounded-lg bg-zinc-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-zinc-700 dark:bg-zinc-100 dark:text-zinc-900 dark:hover:bg-zinc-300">+ New Plan</button>
              </div>
              {plans.length === 0 ? (
                <div className="rounded-2xl border border-zinc-200 bg-white p-12 text-center shadow-sm dark:border-zinc-800 dark:bg-zinc-900">
                  <p className="text-sm text-zinc-400">No plans yet. Create your first pricing plan.</p>
                </div>
              ) : (
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  {plans.map((plan) => (
                    <div key={plan.id} className="rounded-2xl border border-zinc-200 bg-white p-6 shadow-sm dark:border-zinc-800 dark:bg-zinc-900 flex flex-col">
                      <div className="mb-4">
                        <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">{plan.name}</h3>
                        {plan.description && <p className="mt-1 text-xs text-zinc-500">{plan.description}</p>}
                      </div>
                      <div className="mb-4 text-3xl font-bold text-zinc-900 dark:text-zinc-100">
                        {plan.price_dzd.toLocaleString()} <span className="text-sm font-normal text-zinc-500">DZD</span>
                      </div>
                      <div className="space-y-1 text-xs text-zinc-600 dark:text-zinc-400">
                        <div className="flex items-center gap-2">
                          <svg className="h-3.5 w-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                          {plan.max_users} user{plan.max_users > 1 ? "s" : ""}
                        </div>
                        <div className="flex items-center gap-2">
                          <svg className="h-3.5 w-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
                          {plan.duration_days} day{plan.duration_days > 1 ? "s" : ""} duration
                        </div>
                      </div>
                      <div className="mt-auto pt-4">
                        <button onClick={() => handleDeletePlan(plan.id)} className="rounded border border-red-300 px-3 py-1.5 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">Delete</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  );
}