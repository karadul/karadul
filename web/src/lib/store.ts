import { create } from "zustand"

export interface Node {
  id: string
  hostname: string
  virtualIP: string
  publicKey: string
  status: "online" | "offline" | "pending"
  endpoint?: string
  os?: string
  version?: string
  lastSeen?: string
  advertisedRoutes?: string[]
  isExitNode?: boolean
  rxBytes?: number
  txBytes?: number
}

export interface Peer {
  id: string
  hostname: string
  virtualIP: string
  state: "Discovered" | "Connecting" | "Direct" | "Relayed" | "Idle" | "Expired"
  endpoint?: string
  lastHandshake?: string
  rxBytes: number
  txBytes: number
  latency?: number
}

export interface MeshTopology {
  nodes: {
    id: string
    hostname: string
    virtualIP: string
    status: string
    isExitNode?: boolean
  }[]
  connections: {
    from: string
    to: string
    type: "direct" | "relay"
    latency?: number
  }[]
}

export type Topology = MeshTopology

export interface SystemStats {
  uptime: number
  memoryUsage: number
  cpuUsage: number
  goroutines: number
  peersConnected: number
  totalRx: number
  totalTx: number
}

export type Stats = SystemStats

export interface AuthKey {
  id: string
  key: string
  createdAt: string
  expiresAt?: string
  usedBy?: string
}

export interface TrafficPoint {
  time: string
  rx: number
  tx: number
}

const MAX_TRAFFIC_HISTORY = 30

interface KaradulState {
  // Nodes
  nodes: Node[]
  setNodes: (nodes: Node[]) => void

  // Peers
  peers: Peer[]
  setPeers: (peers: Peer[]) => void

  // Topology
  topology: MeshTopology
  setTopology: (topology: MeshTopology) => void

  // Stats
  stats: SystemStats | null
  setStats: (stats: SystemStats) => void

  // Traffic history for real-time chart
  trafficHistory: TrafficPoint[]
  addTrafficPoint: (rx: number, tx: number) => void

  // Selected node for details
  selectedNode: Node | null
  setSelectedNode: (node: Node | null) => void

  // UI State
  darkMode: boolean
  toggleDarkMode: () => void

  // Connection
  isConnected: boolean
  setIsConnected: (connected: boolean) => void

  // Loading states
  isLoading: boolean
  setIsLoading: (loading: boolean) => void
}

export const useKaradulStore = create<KaradulState>((set) => ({
  nodes: [],
  setNodes: (nodes) => set({ nodes }),

  peers: [],
  setPeers: (peers) => set({ peers }),

  topology: { nodes: [], connections: [] },
  setTopology: (topology) => set({ topology }),

  stats: null,
  setStats: (stats) => set({ stats }),

  trafficHistory: [],
  addTrafficPoint: (rx, tx) =>
    set((state) => {
      const point: TrafficPoint = {
        time: new Date().toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        rx,
        tx,
      }
      const history = [...state.trafficHistory, point]
      if (history.length > MAX_TRAFFIC_HISTORY) {
        history.splice(0, history.length - MAX_TRAFFIC_HISTORY)
      }
      return { trafficHistory: history }
    }),

  selectedNode: null,
  setSelectedNode: (node) => set({ selectedNode: node }),

  darkMode: false,
  toggleDarkMode: () => set((state) => ({ darkMode: !state.darkMode })),

  isConnected: false,
  setIsConnected: (connected) => set({ isConnected: connected }),

  isLoading: true,
  setIsLoading: (loading) => set({ isLoading: loading }),
}))
