import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

export function formatRate(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "0/s";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M/s`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K/s`;
  return `${Math.round(n)}/s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes >= 1_099_511_627_776) return `${(bytes / 1_099_511_627_776).toFixed(1)} TB`;
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(1)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024) return `${(bytes / 1_024).toFixed(1)} KB`;
  return `${bytes} B`;
}

export function timeAgo(date: Date | string): string {
  const now = new Date();
  const d = typeof date === "string" ? new Date(date) : date;
  if (isNaN(d.getTime())) return "unknown";
  const seconds = Math.floor((now.getTime() - d.getTime()) / 1000);
  if (seconds < 0) return "just now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function severityColor(severity: number): string {
  if (severity >= 4) return "text-severity-critical";
  if (severity >= 3) return "text-severity-high";
  if (severity >= 2) return "text-severity-medium";
  if (severity >= 1) return "text-severity-low";
  return "text-severity-info";
}

export function severityLabel(severity: number): string {
  if (severity >= 4) return "Critical";
  if (severity >= 3) return "High";
  if (severity >= 2) return "Medium";
  if (severity >= 1) return "Low";
  return "Info";
}

export function severityBgColor(severity: number): string {
  if (severity >= 4) return "bg-red-500/10 text-red-400 border-red-500/20";
  if (severity >= 3) return "bg-amber-500/10 text-amber-400 border-amber-500/20";
  if (severity >= 2) return "bg-blue-500/10 text-blue-400 border-blue-500/20";
  if (severity >= 1) return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
  return "bg-zinc-500/10 text-zinc-400 border-zinc-500/20";
}
