import type { Node, Peer } from "@/lib/store"

interface AuthKeyExport {
  id: string
  key: string
  createdAt: string
  expiresAt?: string
  usedBy?: string
}

/**
 * Convert data to CSV format
 */
export function toCSV<T>(data: T[], columns: (keyof T)[]): string {
  const headers = columns.join(",")
  const rows = data.map((item) =>
    columns
      .map((col) => {
        const value = item[col]
        if (value === null || value === undefined) return ""
        if (typeof value === "string" && value.includes(",")) {
          return `"${value}"`
        }
        return String(value)
      })
      .join(",")
  )
  return [headers, ...rows].join("\n")
}

/**
 * Download data as a file
 */
export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}

/**
 * Export nodes to CSV
 */
export function exportNodesCSV(nodes: Node[]): void {
  const csv = toCSV<Node>(nodes, [
    "id",
    "hostname",
    "virtualIP",
    "status",
    "endpoint",
    "lastSeen",
    "isExitNode",
    "rxBytes",
    "txBytes",
  ])
  downloadFile(csv, `karadul-nodes-${new Date().toISOString().split("T")[0]}.csv`, "text/csv")
}

/**
 * Export nodes to JSON
 */
export function exportNodesJSON(nodes: Node[]): void {
  downloadFile(
    JSON.stringify(nodes, null, 2),
    `karadul-nodes-${new Date().toISOString().split("T")[0]}.json`,
    "application/json"
  )
}

/**
 * Export peers to CSV
 */
export function exportPeersCSV(peers: Peer[]): void {
  const csv = toCSV<Peer>(peers, [
    "id",
    "hostname",
    "virtualIP",
    "state",
    "endpoint",
    "latency",
    "rxBytes",
    "txBytes",
    "lastHandshake",
  ])
  downloadFile(csv, `karadul-peers-${new Date().toISOString().split("T")[0]}.csv`, "text/csv")
}

/**
 * Export peers to JSON
 */
export function exportPeersJSON(peers: Peer[]): void {
  downloadFile(
    JSON.stringify(peers, null, 2),
    `karadul-peers-${new Date().toISOString().split("T")[0]}.json`,
    "application/json"
  )
}

/**
 * Export auth keys to CSV
 * @internal Test-only export — not used in production code
 */
export function exportAuthKeysCSV(keys: AuthKeyExport[]): void {
  const csv = toCSV<AuthKeyExport>(keys, ["id", "key", "createdAt", "expiresAt", "usedBy"])
  downloadFile(csv, `karadul-auth-keys-${new Date().toISOString().split("T")[0]}.csv`, "text/csv")
}
