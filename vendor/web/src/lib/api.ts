const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("aup_token");
}

export function logout() {
  localStorage.removeItem("aup_token");
  localStorage.removeItem("aup_username");
  window.location.href = "/login";
}

export async function apiFetch(path: string, options?: RequestInit) {
  const token = getToken();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options?.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_URL}${path}`, { ...options, headers });
  if (res.status === 401) {
    logout();
    throw new Error("Unauthorized");
  }
  return res;
}

export async function apiFetchMultipart(path: string, formData: FormData) {
  const token = getToken();
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_URL}${path}`, { method: "POST", headers, body: formData });
  if (res.status === 401) { logout(); throw new Error("Unauthorized"); }
  return res;
}

// ─── Auth ────────────────────────────────────────────────────────────────────
export async function login(username: string, password: string): Promise<{ token: string; username: string }> {
  const res = await fetch(`${API_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) throw new Error("Invalid credentials");
  return res.json();
}

// ─── License ─────────────────────────────────────────────────────────────────
export interface License {
  id: number;
  license_key: string;
  fingerprint: string;
  signature: string;
  max_users: number;
  issued_at: string;
  expires_at: string;
  created_at: string;
}

export async function generateLicense(data: {
  fingerprint: string;
  max_users: number;
  issued_at: string;
  expires_at: string;
}): Promise<License> {
  const res = await apiFetch("/api/license/generate", {
    method: "POST",
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to generate license");
  return res.json();
}

export async function listLicenses(): Promise<License[]> {
  const res = await apiFetch("/api/license");
  if (!res.ok) throw new Error("Failed to fetch licenses");
  return res.json();
}

export async function deleteLicense(id: number): Promise<void> {
  const res = await apiFetch(`/api/license/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete license");
}

// ─── Public: lookup license by fingerprint ────────────────────────────────────
export async function lookupLicense(fingerprint: string): Promise<License | null> {
  const res = await fetch(`${API_URL}/api/license/lookup/${encodeURIComponent(fingerprint)}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Failed to lookup license");
  return res.json();
}

// ─── Customer Requests ───────────────────────────────────────────────────────
export interface CustomerRequest {
  id: number;
  name: string;
  email: string;
  fingerprint: string;
  note: string;
  status: "pending" | "approved" | "rejected";
  created_at: string;
}

export async function submitLicenseRequest(data: {
  name: string;
  email: string;
  fingerprint: string;
  note?: string;
}): Promise<void> {
  const res = await fetch(`${API_URL}/api/license/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to submit request");
}

export async function listRequests(): Promise<CustomerRequest[]> {
  const res = await apiFetch("/api/license/requests");
  if (!res.ok) throw new Error("Failed to fetch requests");
  return res.json();
}

export async function updateRequestStatus(id: number, status: string): Promise<void> {
  const res = await apiFetch(`/api/license/requests/${id}`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
  });
  if (!res.ok) throw new Error("Failed to update request");
}

// ─── Renew ───────────────────────────────────────────────────────────────────
export interface RenewResult {
  ok: boolean;
  fingerprint: string;
  new_expires_at: string;
  entries_count: number;
}

export async function renewLicense(file: File): Promise<RenewResult> {
  const formData = new FormData();
  formData.append("audit_file", file);
  const res = await apiFetchMultipart("/api/license/renew", formData);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Failed to renew" }));
    throw new Error(err.error || "Failed to renew license");
  }
  return res.json();
}

// ─── Audit Logs ──────────────────────────────────────────────────────────────
export interface AuditLog {
  id: number;
  fingerprint: string;
  entries: string[];
  uploaded_at: string;
}

export async function getAuditLogs(fingerprint: string): Promise<AuditLog[]> {
  const res = await apiFetch(`/api/license/audit/${encodeURIComponent(fingerprint)}`);
  if (!res.ok) throw new Error("Failed to fetch audit logs");
  return res.json();
}

// ─── Customer Auth ───────────────────────────────────────────────────────────
export async function customerLogin(fingerprint: string): Promise<{ token: string; fingerprint: string }> {
  const res = await fetch(`${API_URL}/api/auth/customer-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fingerprint }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: "Login failed" }));
    throw new Error(err.error || "Login failed");
  }
  return res.json();
}

export async function getMyLicense(): Promise<License> {
  const res = await apiFetch("/api/license/my");
  if (!res.ok) throw new Error("Failed to fetch license");
  return res.json();
}

// ─── Plans ──────────────────────────────────────────────────────────────────
export interface Plan {
  id: number;
  name: string;
  price_dzd: number;
  max_users: number;
  duration_days: number;
  description: string;
  created_at: string;
}

export async function listPlans(): Promise<Plan[]> {
  const res = await apiFetch("/api/plans");
  if (!res.ok) throw new Error("Failed to fetch plans");
  return res.json();
}

export async function createPlan(data: {
  name: string;
  price_dzd: number;
  max_users: number;
  duration_days: number;
  description?: string;
}): Promise<Plan> {
  const res = await apiFetch("/api/plans", {
    method: "POST",
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to create plan");
  return res.json();
}

export async function updatePlan(id: number, data: {
  name: string;
  price_dzd: number;
  max_users: number;
  duration_days: number;
  description?: string;
}): Promise<Plan> {
  const res = await apiFetch(`/api/plans/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error("Failed to update plan");
  return res.json();
}

export async function deletePlan(id: number): Promise<void> {
  const res = await apiFetch(`/api/plans/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete plan");
}
