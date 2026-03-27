import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import type { ReactNode } from "react"
import {
  useNodes,
  usePeers,
  useTopology,
  useStats,
  useAuthKeys,
  useDeleteNode,
  useCreateAuthKey,
  useDeleteAuthKey,
  useACL,
  useUpdateACL,
  queryKeys,
} from "./api"
import { mockNodes, mockPeers, mockTopology, mockStats, mockAuthKeys } from "@/test/mocks"

// Mock fetch globally
const mockFetch = vi.fn()
global.fetch = mockFetch

// Mock sonner toast
vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

// Create wrapper for tests
function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  })

  return function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    )
  }
}

describe("API Hooks", () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  describe("queryKeys", () => {
    it("should have correct query keys", () => {
      expect(queryKeys.nodes).toEqual(["nodes"])
      expect(queryKeys.peers).toEqual(["peers"])
      expect(queryKeys.topology).toEqual(["topology"])
      expect(queryKeys.stats).toEqual(["stats"])
      expect(queryKeys.node("123")).toEqual(["nodes", "123"])
    })
  })

  describe("useNodes", () => {
    it("should fetch nodes successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockNodes),
      })

      const { result } = renderHook(() => useNodes(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockNodes)
    })

    it("should handle fetch error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve("Network error"),
      })

      const { result } = renderHook(() => useNodes(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isError).toBe(true))
      expect(result.current.error).toBeInstanceOf(Error)
    })

    it("should handle fetch error with no message", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve(""),
      })

      const { result } = renderHook(() => useNodes(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isError).toBe(true))
      expect(result.current.error).toBeInstanceOf(Error)
      expect(result.current.error?.message).toBe("HTTP 500")
    })
  })

  describe("usePeers", () => {
    it("should fetch peers successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockPeers),
      })

      const { result } = renderHook(() => usePeers(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockPeers)
    })
  })

  describe("useTopology", () => {
    it("should fetch topology successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockTopology),
      })

      const { result } = renderHook(() => useTopology(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockTopology)
    })
  })

  describe("useStats", () => {
    it("should fetch stats successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockStats),
      })

      const { result } = renderHook(() => useStats(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockStats)
    })
  })

  describe("useAuthKeys", () => {
    it("should fetch auth keys successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockAuthKeys),
      })

      const { result } = renderHook(() => useAuthKeys(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockAuthKeys)
    })
  })

  describe("useDeleteNode", () => {
    it("should delete node successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      })

      const { result } = renderHook(() => useDeleteNode(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("node-1")

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })

    it("should handle delete node error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve("Failed to delete"),
      })

      const { result } = renderHook(() => useDeleteNode(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("node-1")

      await waitFor(() => expect(result.current.isError).toBe(true))
    })
  })

  describe("useCreateAuthKey", () => {
    it("should create auth key successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockAuthKeys[0]),
      })

      const { result } = renderHook(() => useCreateAuthKey(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("24h")

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })

    it("should create auth key without expiration", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockAuthKeys[0]),
      })

      const { result } = renderHook(() => useCreateAuthKey(), {
        wrapper: createWrapper(),
      })

      result.current.mutate(undefined)

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })

    it("should handle create auth key error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve("Failed to create"),
      })

      const { result } = renderHook(() => useCreateAuthKey(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("24h")

      await waitFor(() => expect(result.current.isError).toBe(true))
    })
  })

  describe("useDeleteAuthKey", () => {
    it("should delete auth key successfully", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      })

      const { result } = renderHook(() => useDeleteAuthKey(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("key-1")

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })

    it("should handle delete auth key error", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve("Failed to delete"),
      })

      const { result } = renderHook(() => useDeleteAuthKey(), {
        wrapper: createWrapper(),
      })

      result.current.mutate("key-1")

      await waitFor(() => expect(result.current.isError).toBe(true))
    })
  })

  describe("useACL", () => {
    it("should fetch ACL successfully", async () => {
      const mockACL = {
        rules: [
          {
            action: "accept" as const,
            src: ["*"],
            dst: ["*:*"],
          },
        ],
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockACL),
      })

      const { result } = renderHook(() => useACL(), {
        wrapper: createWrapper(),
      })

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data).toEqual(mockACL)
    })
  })

  describe("useUpdateACL", () => {
    it("should update ACL successfully", async () => {
      const rules = [
        {
          action: "accept" as const,
          src: ["*"],
          dst: ["*:*"],
        },
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      })

      const { result } = renderHook(() => useUpdateACL(), {
        wrapper: createWrapper(),
      })

      result.current.mutate(rules)

      await waitFor(() => expect(result.current.isSuccess).toBe(true))
    })

    it("should handle update ACL error", async () => {
      const rules = [
        {
          action: "accept" as const,
          src: ["*"],
          dst: ["*:*"],
        },
      ]

      mockFetch.mockResolvedValueOnce({
        ok: false,
        text: () => Promise.resolve("Failed to update"),
      })

      const { result } = renderHook(() => useUpdateACL(), {
        wrapper: createWrapper(),
      })

      result.current.mutate(rules)

      await waitFor(() => expect(result.current.isError).toBe(true))
    })
  })
})
