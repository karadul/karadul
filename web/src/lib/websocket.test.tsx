import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { renderHook, act } from "@testing-library/react"
import { WebSocketProvider, useWebSocket } from "./websocket"
import type { ReactNode } from "react"
import { createTestQueryClient } from "@/test/utils"
import { QueryClientProvider } from "@tanstack/react-query"
import { useKaradulStore } from "./store"

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  readyState = MockWebSocket.OPEN
  onopen: ((event: Event) => void) | null = null
  onclose: ((event: CloseEvent) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onerror: ((event: Event) => void) | null = null

  constructor(public url: string) {
    // Simulate async connection
    setTimeout(() => {
      if (this.onopen) {
        this.onopen(new Event("open"))
      }
    }, 0)
  }

  send = vi.fn()
  close = vi.fn()
}

// Store original WebSocket
const OriginalWebSocket = global.WebSocket

function createWrapper() {
  const queryClient = createTestQueryClient()

  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>
        <WebSocketProvider>{children}</WebSocketProvider>
      </QueryClientProvider>
    )
  }
}

describe("WebSocketProvider", () => {
  beforeEach(() => {
    vi.useFakeTimers()
    global.WebSocket = MockWebSocket as unknown as typeof WebSocket
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
    global.WebSocket = OriginalWebSocket
  })

  it("should provide WebSocket context", () => {
    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    expect(result.current).toHaveProperty("connected")
    expect(result.current).toHaveProperty("error")
  })

  it("should start disconnected", () => {
    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    expect(result.current.connected).toBe(false)
  })

  it("should connect to WebSocket", async () => {
    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    expect(result.current.connected).toBe(false)

    // Wait for connection
    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    expect(result.current.connected).toBe(true)
  })

  it("should set error to null on successful connection", async () => {
    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    expect(result.current.error).toBeNull()
  })

  it("should handle custom URL", async () => {
    const customUrl = "wss://custom.example.com/ws"

    const wrapper = () => {
      const queryClient = createTestQueryClient()
      return function Wrapper({ children }: { children: ReactNode }) {
        return (
          <QueryClientProvider client={queryClient}>
            <WebSocketProvider url={customUrl}>{children}</WebSocketProvider>
          </QueryClientProvider>
        )
      }
    }

    const { result } = renderHook(() => useWebSocket(), {
      wrapper: wrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    expect(result.current.connected).toBe(true)
  })
})

describe("WebSocketProvider - Message handling", () => {
  let mockWs: MockWebSocket | null = null

  beforeEach(() => {
    vi.useFakeTimers()

    // Create a mock that captures the instance
    class CapturingMockWebSocket extends MockWebSocket {
      constructor(url: string) {
        super(url)
        mockWs = this
        setTimeout(() => {
          if (this.onopen) {
            this.onopen(new Event("open"))
          }
        }, 0)
      }
    }

    global.WebSocket = CapturingMockWebSocket as unknown as typeof WebSocket
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
    mockWs = null
    global.WebSocket = OriginalWebSocket
  })

  it("should handle 'nodes' message type", async () => {
    const setNodesSpy = vi.spyOn(useKaradulStore.getState(), "setNodes")

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    // Simulate receiving a nodes message
    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: JSON.stringify({
            type: "nodes",
            data: [{ id: "1", hostname: "test" }],
          }),
        } as MessageEvent)
      }
    })

    expect(setNodesSpy).toHaveBeenCalled()
  })

  it("should handle 'peers' message type", async () => {
    const setPeersSpy = vi.spyOn(useKaradulStore.getState(), "setPeers")

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: JSON.stringify({
            type: "peers",
            data: [{ id: "1", hostname: "peer" }],
          }),
        } as MessageEvent)
      }
    })

    expect(setPeersSpy).toHaveBeenCalled()
  })

  it("should handle 'topology' message type", async () => {
    const setTopologySpy = vi.spyOn(useKaradulStore.getState(), "setTopology")

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: JSON.stringify({
            type: "topology",
            data: { nodes: [], connections: [] },
          }),
        } as MessageEvent)
      }
    })

    expect(setTopologySpy).toHaveBeenCalled()
  })

  it("should handle 'stats' message type", async () => {
    const setStatsSpy = vi.spyOn(useKaradulStore.getState(), "setStats")

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: JSON.stringify({
            type: "stats",
            data: { uptime: 1000, cpuUsage: 50 },
          }),
        } as MessageEvent)
      }
    })

    expect(setStatsSpy).toHaveBeenCalled()
  })

  it("should warn on unknown message type", async () => {
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {})

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: JSON.stringify({
            type: "unknown",
            data: {},
          }),
        } as MessageEvent)
      }
    })

    expect(consoleSpy).toHaveBeenCalledWith("Unknown message type:", "unknown")

    consoleSpy.mockRestore()
  })

  it("should handle invalid JSON in message", async () => {
    const consoleSpy = vi.spyOn(console, "error").mockImplementation(() => {})

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    act(() => {
      if (mockWs?.onmessage) {
        mockWs.onmessage({
          data: "invalid json",
        } as MessageEvent)
      }
    })

    expect(consoleSpy).toHaveBeenCalled()

    consoleSpy.mockRestore()
  })
})

describe("WebSocketProvider - Connection handling", () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it("should handle connection close and reconnect", async () => {
    vi.useFakeTimers()

    let wsInstance: MockWebSocket | null = null

    class ReconnectingMockWebSocket extends MockWebSocket {
      constructor(url: string) {
        super(url)
        wsInstance = this
      }
    }

    global.WebSocket = ReconnectingMockWebSocket as unknown as typeof WebSocket

    renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    // Wait for initial connection
    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    // Simulate close
    act(() => {
      if (wsInstance?.onclose) {
        wsInstance.onclose(new CloseEvent("close"))
      }
    })

    // Wait for reconnect timeout
    await act(async () => {
      vi.advanceTimersByTime(3000)
    })
  })

  it("should handle WebSocket error", async () => {
    vi.useFakeTimers()

    let wsInstance: MockWebSocket | null = null

    class ErrorMockWebSocket extends MockWebSocket {
      constructor(url: string) {
        super(url)
        wsInstance = this
      }
    }

    global.WebSocket = ErrorMockWebSocket as unknown as typeof WebSocket

    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    // Simulate error
    act(() => {
      if (wsInstance?.onerror) {
        wsInstance.onerror(new Event("error"))
      }
    })

    expect(result.current.error).toBe("WebSocket connection failed")
    expect(wsInstance?.close).toHaveBeenCalled()
  })

  it("should handle WebSocket constructor throwing an error", async () => {
    vi.useFakeTimers()

    // Mock WebSocket constructor that throws
    class ThrowingMockWebSocket {
      static CONNECTING = 0
      static OPEN = 1
      static CLOSING = 2
      static CLOSED = 3

      constructor() {
        throw new Error("WebSocket not available")
      }
    }

    global.WebSocket = ThrowingMockWebSocket as unknown as typeof WebSocket

    const { result } = renderHook(() => useWebSocket(), {
      wrapper: createWrapper(),
    })

    // Wait for the error to be set
    await act(async () => {
      vi.advanceTimersByTime(100)
    })

    expect(result.current.error).toBe("Failed to connect to WebSocket")

    // Wait for reconnect attempt
    await act(async () => {
      vi.advanceTimersByTime(3000)
    })
  })
})
