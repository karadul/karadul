import type { Node, Peer, MeshTopology, SystemStats } from "@/lib/store"
import type { AuthKey, ACLRule } from "@/lib/api"

// Mock data for development
const mockNodes: Node[] = [
  {
    id: "node-1",
    hostname: "server-01",
    virtualIP: "100.64.0.1",
    publicKey: "pubkey1abc123...",
    status: "online",
    endpoint: "203.0.113.1:51820",
    lastSeen: new Date().toISOString(),
    routes: ["10.0.0.0/24"],
    isExitNode: true,
    rxBytes: 1024 * 1024 * 1024 * 2.5,
    txBytes: 1024 * 1024 * 1024 * 1.8,
  },
  {
    id: "node-2",
    hostname: "laptop-alice",
    virtualIP: "100.64.0.2",
    publicKey: "pubkey2def456...",
    status: "online",
    endpoint: "198.51.100.5:51820",
    lastSeen: new Date().toISOString(),
    isExitNode: false,
    rxBytes: 1024 * 1024 * 500,
    txBytes: 1024 * 1024 * 300,
  },
  {
    id: "node-3",
    hostname: "phone-bob",
    virtualIP: "100.64.0.3",
    publicKey: "pubkey3ghi789...",
    status: "offline",
    endpoint: "192.0.2.10:51820",
    lastSeen: new Date(Date.now() - 86400000).toISOString(),
    isExitNode: false,
    rxBytes: 1024 * 1024 * 100,
    txBytes: 1024 * 1024 * 150,
  },
  {
    id: "node-4",
    hostname: "desktop-carol",
    virtualIP: "100.64.0.4",
    publicKey: "pubkey4jkl012...",
    status: "online",
    endpoint: "198.51.100.20:51820",
    lastSeen: new Date().toISOString(),
    isExitNode: false,
    rxBytes: 1024 * 1024 * 1024 * 0.8,
    txBytes: 1024 * 1024 * 1024 * 0.5,
  },
  {
    id: "node-5",
    hostname: "tablet-dave",
    virtualIP: "100.64.0.5",
    publicKey: "pubkey5mno345...",
    status: "pending",
    isExitNode: false,
    rxBytes: 0,
    txBytes: 0,
  },
]

const mockPeers: Peer[] = [
  {
    id: "peer-1",
    hostname: "laptop-alice",
    virtualIP: "100.64.0.2",
    state: "Direct",
    endpoint: "198.51.100.5:51820",
    lastHandshake: new Date(Date.now() - 120000).toISOString(),
    rxBytes: 1024 * 1024 * 500,
    txBytes: 1024 * 1024 * 300,
    latency: 25,
  },
  {
    id: "peer-2",
    hostname: "phone-bob",
    virtualIP: "100.64.0.3",
    state: "Relayed",
    endpoint: "relay.karadul.local:3478",
    lastHandshake: new Date(Date.now() - 300000).toISOString(),
    rxBytes: 1024 * 1024 * 100,
    txBytes: 1024 * 1024 * 150,
    latency: 85,
  },
  {
    id: "peer-3",
    hostname: "desktop-carol",
    virtualIP: "100.64.0.4",
    state: "Direct",
    endpoint: "198.51.100.20:51820",
    lastHandshake: new Date(Date.now() - 60000).toISOString(),
    rxBytes: 1024 * 1024 * 1024 * 0.8,
    txBytes: 1024 * 1024 * 1024 * 0.5,
    latency: 15,
  },
  {
    id: "peer-4",
    hostname: "tablet-dave",
    virtualIP: "100.64.0.5",
    state: "Idle",
    lastHandshake: new Date(Date.now() - 3600000).toISOString(),
    rxBytes: 1024 * 1024 * 50,
    txBytes: 1024 * 1024 * 30,
  },
  {
    id: "peer-5",
    hostname: "vpn-gateway",
    virtualIP: "100.64.0.10",
    state: "Connecting",
    rxBytes: 0,
    txBytes: 0,
  },
]

const mockTopology: MeshTopology = {
  nodes: mockNodes,
  connections: [
    { from: "node-1", to: "node-2", type: "direct", latency: 25 },
    { from: "node-1", to: "node-3", type: "relay", latency: 85 },
    { from: "node-1", to: "node-4", type: "direct", latency: 15 },
    { from: "node-2", to: "node-4", type: "direct", latency: 35 },
    { from: "node-3", to: "node-5", type: "relay", latency: 120 },
  ],
}

const mockStats: SystemStats = {
  uptime: 86400 * 3 + 3600 * 5 + 1800,
  memoryUsage: 1024 * 1024 * 256,
  cpuUsage: 12.5,
  goroutines: 47,
  peersConnected: 3,
  totalRx: 1024 * 1024 * 1024 * 5.2,
  totalTx: 1024 * 1024 * 1024 * 3.8,
}

const mockAuthKeys: AuthKey[] = [
  {
    id: "key-1",
    key: "kdl_auth_abc123def456ghi789",
    createdAt: new Date(Date.now() - 86400000 * 7).toISOString(),
    ephemeral: true,
    used: true,
  },
  {
    id: "key-2",
    key: "kdl_auth_jkl012mno345pqr678",
    createdAt: new Date(Date.now() - 86400000 * 3).toISOString(),
    expiresAt: new Date(Date.now() + 86400000 * 4).toISOString(),
    ephemeral: false,
    used: false,
  },
  {
    id: "key-3",
    key: "kdl_auth_stu901vwx234yz5678",
    createdAt: new Date().toISOString(),
    ephemeral: false,
    used: false,
  },
]

const mockACL: ACLRule[] = [
  {
    action: "allow",
    src: ["100.64.0.0/10"],
    dst: ["100.64.0.0/10"],
    ports: ["*"],
  },
  {
    action: "allow",
    src: ["100.64.0.0/10"],
    dst: ["0.0.0.0/0"],
    ports: ["53/udp"],
  },
  {
    action: "deny",
    src: ["100.64.0.0/10"],
    dst: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  },
]

// Simulate network delay
const delay = (ms: number = 300) => new Promise((resolve) => setTimeout(resolve, ms))

// Mock API client
/** @internal Test-only export — not used in production code */
export const mockApi = {
  // Nodes
  async getNodes(): Promise<Node[]> {
    await delay()
    return [...mockNodes]
  },

  async deleteNode(id: string): Promise<void> {
    await delay()
    const index = mockNodes.findIndex((n) => n.id === id)
    if (index !== -1) {
      mockNodes.splice(index, 1)
    }
  },

  // Peers
  async getPeers(): Promise<Peer[]> {
    await delay()
    return [...mockPeers]
  },

  // Topology
  async getTopology(): Promise<MeshTopology> {
    await delay()
    return { ...mockTopology, nodes: [...mockNodes], connections: [...mockTopology.connections] }
  },

  // Stats
  async getStats(): Promise<SystemStats> {
    await delay(200)
    // Simulate slight variations in stats
    return {
      ...mockStats,
      cpuUsage: Math.max(5, Math.min(50, mockStats.cpuUsage + (Math.random() - 0.5) * 5)),
      memoryUsage: mockStats.memoryUsage + Math.floor(Math.random() * 1000000),
    }
  },

  // Auth Keys
  async getAuthKeys(): Promise<AuthKey[]> {
    await delay()
    return [...mockAuthKeys]
  },

  async createAuthKey(expiresIn?: string): Promise<AuthKey> {
    await delay()
    const newKey: AuthKey = {
      id: `key-${Date.now()}`,
      key: `kdl_auth_${Math.random().toString(36).substring(2, 15)}`,
      createdAt: new Date().toISOString(),
      expiresAt: expiresIn
        ? new Date(Date.now() + parseDuration(expiresIn)).toISOString()
        : undefined,
      ephemeral: false,
      used: false,
    }
    mockAuthKeys.push(newKey)
    return newKey
  },

  async deleteAuthKey(id: string): Promise<void> {
    await delay()
    const index = mockAuthKeys.findIndex((k) => k.id === id)
    if (index !== -1) {
      mockAuthKeys.splice(index, 1)
    }
  },

  // ACL
  async getACL(): Promise<{ rules: ACLRule[] }> {
    await delay()
    return { rules: [...mockACL] }
  },

  async updateACL(rules: ACLRule[]): Promise<void> {
    await delay()
    mockACL.length = 0
    mockACL.push(...rules)
  },
}

// Helper to parse duration strings like "1h", "7d", etc.
function parseDuration(duration: string): number {
  const match = duration.match(/^(\d+)([hd])$/)
  if (!match) return 0
  const [, num, unit] = match
  const multiplier = unit === "h" ? 3600000 : 86400000
  return parseInt(num) * multiplier
}

// Check if we should use mock API - only when explicitly enabled via env var
/** @internal Test-only export — not used in production code */
export const shouldUseMockApi = (): boolean => {
  return import.meta.env.VITE_USE_MOCK_API === "true"
}
