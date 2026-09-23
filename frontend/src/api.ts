import { useEffect, useState, useCallback, useRef } from "react";
export type Monitor = { state: string; message: string; updated: number };
export type Health = {
  active_alerts: EventList;
  port: number;
  status: string;
  version: string;
  sample_seconds: number;
  sampling_ok: boolean;
  monitors: Record<string, Monitor>;
};
export type Sample = {
  timestamp: number;
  cpu: number;
  ram: number;
  disk: number;
};
export type Stats = {
  timestamp: number;
  hostname: string;
  platform: string;
  release: string;
  cpu: number;
  cores: number;
  ram: { percent: number; used: number; total: number };
  disk: { percent: number; used: number; total: number };
  uptime: number;
  load: number[];
  history: Sample[];
};
export type Event = {
  id: number;
  timestamp: number;
  type: string;
  category: string;
  source_ip: string | null;
  severity: string;
  description: string;
  details: Record<string, unknown>;
};
export type EventList = { total: number; items: Event[] };
export type Port = {
  port: number;
  protocol: string;
  address: string;
  process: string | null;
  service: string;
  exposure: string;
};
export type User = {
  username: string;
  uid: number;
  home: string;
  shell: string;
  interactive: boolean;
};
export type Score = {
  score: number;
  label: string;
  deductions: { reason: string; points: number }[];
  unknown: string[];
  description: string;
  firewall: string;
};
export type SSH = {
  threshold: number;
  window: number;
  failed_24h: number;
  successful_24h: number;
  attacks_24h: number;
  incidents: Event[];
};
export type Scans = {
  threshold: number;
  window: number;
  scans_24h: number;
  incidents: Event[];
};
export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch("/api" + path, {
    credentials: "same-origin",
    ...options,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request failed (${response.status}).`,
    );
  }
  return response.json();
}
export function useApi<T>(path: string, interval = 5000) {
  const [data, setData] = useState<T>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((x) => x + 1), []);
  useEffect(() => {
    window.addEventListener("vpsentry:refresh", refresh);
    return () => window.removeEventListener("vpsentry:refresh", refresh);
  }, [refresh]);
  const previousPath = useRef(path);
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    if (previousPath.current !== path) {
      setData(undefined);
      previousPath.current = path;
    }
    setLoading(true);
    async function load() {
      try {
        const value = await api<T>(path, { signal: controller.signal });
        setData(value);
        setError("");
      } catch (e) {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : "Cannot reach the server.");
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
          timer = setTimeout(load, interval);
        }
      }
    }
    void load();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [path, interval, revision]);
  return { data, error, loading, refresh };
}
export const bytes = (n: number) => `${(n / 1073741824).toFixed(1)} GB`;
export const duration = (n: number) =>
  n >= 86400
    ? `${Math.floor(n / 86400)}d ${Math.floor((n % 86400) / 3600)}h`
    : `${Math.floor(n / 3600)}h ${Math.floor((n % 3600) / 60)}m`;
export const time = (n: number) =>
  new Date(n * 1000).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
export const title = (s: string) =>
  s
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\bssh\b/g, "SSH")
    .replace(/^./, (c) => c.toUpperCase());

export const refreshAll = () =>
  window.dispatchEvent(new window.Event("vpsentry:refresh"));
