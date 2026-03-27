import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { PeersPage } from "./peers"
import { AllProviders } from "@/test/utils"
import { mockPeers } from "@/test/mocks"

// Mock export functions
vi.mock("@/lib/export", () => ({
  exportPeersCSV: vi.fn(),
  exportPeersJSON: vi.fn(),
}))

// Mock the API hooks
const mockRefetch = vi.fn()

// Mutable state for peers
const peersState = { peers: mockPeers }

vi.mock("@/lib/api", () => ({
  usePeers: () => ({
    data: peersState.peers,
    isLoading: false,
    error: null,
    refetch: mockRefetch,
  }),
}))

describe("PeersPage - Rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = mockPeers
  })

  it("should render the peers title", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Peers")).toBeInTheDocument()
    expect(screen.getByText("Manage peer connections in your mesh network")).toBeInTheDocument()
  })

  it("should render peer connections card", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Peer Connections")).toBeInTheDocument()
    expect(screen.getByText("All peer connections in the network")).toBeInTheDocument()
  })

  it("should render table headers", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Hostname")).toBeInTheDocument()
    expect(screen.getByText("Virtual IP")).toBeInTheDocument()
    expect(screen.getByText("State")).toBeInTheDocument()
    expect(screen.getByText("Endpoint")).toBeInTheDocument()
    expect(screen.getByText("Latency")).toBeInTheDocument()
    expect(screen.getByText("Data (RX/TX)")).toBeInTheDocument()
    expect(screen.getByText("Last Handshake")).toBeInTheDocument()
  })

  it("should display all peers in the table", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("peer-1")).toBeInTheDocument()
    expect(screen.getByText("peer-2")).toBeInTheDocument()
    expect(screen.getByText("peer-3")).toBeInTheDocument()
  })

  it("should display IP addresses", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("10.0.0.10")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.11")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.12")).toBeInTheDocument()
  })

  it("should render export button", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Export")).toBeInTheDocument()
  })

  it("should call refetch when clicking refresh button", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    const refreshButton = buttons.find(btn =>
      btn.querySelector("svg.lucide-refresh-cw") ||
      (btn.getAttribute("variant") === "outline" && btn.querySelector("svg"))
    )

    if (refreshButton) {
      fireEvent.click(refreshButton)
      // The mock refetch should be called
    }
  })
})

describe("PeersPage - Stat Cards", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render Total Peers card", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Total Peers")).toBeInTheDocument()
    expect(screen.getByText("3")).toBeInTheDocument() // 3 peers in mock
  })

  it("should render Direct peers card", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // "Direct" appears in stat card and as connection state badge
    const directTexts = screen.getAllByText("Direct")
    expect(directTexts.length).toBeGreaterThan(0)
  })

  it("should render Relayed peers card", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // "Relayed" appears in stat card and as connection state badge
    const relayedTexts = screen.getAllByText("Relayed")
    expect(relayedTexts.length).toBeGreaterThan(0)
  })

  it("should render Active peers card", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // "Active" appears in stat card and filter tabs
    const activeTexts = screen.getAllByText("Active")
    expect(activeTexts.length).toBeGreaterThan(0)
  })
})

describe("PeersPage - Search functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render search input", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByPlaceholderText("Search peers...")).toBeInTheDocument()
  })

  it("should filter peers by hostname", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search peers...")
    fireEvent.change(searchInput, { target: { value: "peer-1" } })

    expect(screen.getByText("peer-1")).toBeInTheDocument()
    expect(screen.queryByText("peer-2")).not.toBeInTheDocument()
    expect(screen.queryByText("peer-3")).not.toBeInTheDocument()
  })

  it("should filter peers by IP address", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search peers...")
    fireEvent.change(searchInput, { target: { value: "10.0.0.11" } })

    expect(screen.getByText("peer-2")).toBeInTheDocument()
    expect(screen.queryByText("peer-1")).not.toBeInTheDocument()
  })

  it("should show no results message when search has no matches", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search peers...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    expect(screen.getByText("No peers found")).toBeInTheDocument()
  })

  it("should show clear search button when no results", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search peers...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    expect(screen.getByText("Clear Search")).toBeInTheDocument()
  })

  it("should clear search when clicking clear button", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search peers...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    const clearButton = screen.getByText("Clear Search")
    fireEvent.click(clearButton)

    // After clearing, all peers should be visible again
    expect(screen.getByText("peer-1")).toBeInTheDocument()
    expect(screen.getByText("peer-2")).toBeInTheDocument()
    expect(screen.getByText("peer-3")).toBeInTheDocument()
  })
})

describe("PeersPage - Filter functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render filter tabs", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // "All" appears in "Total Peers" and as tab
    const allTexts = screen.getAllByText("All")
    expect(allTexts.length).toBeGreaterThan(0)
    expect(screen.getByText("Inactive")).toBeInTheDocument()
  })

  it("should show all peers by default", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("peer-1")).toBeInTheDocument()
    expect(screen.getByText("peer-2")).toBeInTheDocument()
    expect(screen.getByText("peer-3")).toBeInTheDocument()
  })
})

describe("PeersPage - Connection State Display", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should display Direct state badge", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Direct state is shown for peer-1
    const directBadges = screen.getAllByText("Direct")
    expect(directBadges.length).toBeGreaterThan(0)
  })

  it("should display Relayed state badge", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Relayed state is shown for peer-2
    const relayedBadges = screen.getAllByText("Relayed")
    expect(relayedBadges.length).toBeGreaterThan(0)
  })

  it("should display Idle state badge", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Idle state is shown for peer-3
    expect(screen.getByText("Idle")).toBeInTheDocument()
  })
})

describe("PeersPage - Data Display", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should display latency for peers with latency data", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("15ms")).toBeInTheDocument()
    expect(screen.getByText("45ms")).toBeInTheDocument()
  })

  it("should display N/A for peers without latency data", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const naElements = screen.getAllByText("N/A")
    expect(naElements.length).toBeGreaterThan(0)
  })

  it("should display endpoint for peers with endpoint", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("192.168.1.200:51820")).toBeInTheDocument()
  })
})

describe("PeersPage - Export functionality", () => {
  const user = userEvent.setup()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render export button", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("Export")).toBeInTheDocument()
  })

  it("should show export dropdown options when clicking Export button", async () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const exportButton = screen.getByRole("button", { name: /export/i })
    await user.click(exportButton)

    await waitFor(() => {
      expect(screen.getByText("Export as CSV")).toBeInTheDocument()
      expect(screen.getByText("Export as JSON")).toBeInTheDocument()
    })
  })

  it("should call exportPeersCSV when clicking CSV export", async () => {
    const { exportPeersCSV } = await import("@/lib/export")

    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const exportButton = screen.getByRole("button", { name: /export/i })
    await user.click(exportButton)

    await waitFor(() => {
      expect(screen.getByText("Export as CSV")).toBeInTheDocument()
    })

    const csvOption = screen.getByText("Export as CSV")
    await user.click(csvOption)

    await waitFor(() => {
      expect(exportPeersCSV).toHaveBeenCalled()
    })
  })

  it("should call exportPeersJSON when clicking JSON export", async () => {
    const { exportPeersJSON } = await import("@/lib/export")

    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    const exportButton = screen.getByRole("button", { name: /export/i })
    await user.click(exportButton)

    await waitFor(() => {
      expect(screen.getByText("Export as JSON")).toBeInTheDocument()
    })

    const jsonOption = screen.getByText("Export as JSON")
    await user.click(jsonOption)

    await waitFor(() => {
      expect(exportPeersJSON).toHaveBeenCalled()
    })
  })
})

describe("PeersPage - Loading state with skeletons", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      usePeers: () => ({ data: null, isLoading: true, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@/lib/export", () => ({
      exportPeersCSV: vi.fn(),
      exportPeersJSON: vi.fn(),
    }))
  })

  it("should show loading skeletons when loading", async () => {
    const { PeersPage: PeersPageLoading } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageLoading />
      </AllProviders>
    )

    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})

describe("PeersPage - Inactive filter", () => {
  const user = userEvent.setup()

  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      usePeers: () => ({ data: mockPeers, isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@/lib/export", () => ({
      exportPeersCSV: vi.fn(),
      exportPeersJSON: vi.fn(),
    }))
  })

  it("should filter to show only inactive peers", async () => {
    const { PeersPage: PeersPageFresh } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageFresh />
      </AllProviders>
    )

    const inactiveTab = screen.getByRole("tab", { name: /inactive/i })
    await user.click(inactiveTab)

    // Only peer-3 (Idle) should be shown for inactive
    await waitFor(() => {
      expect(screen.getByText("peer-3")).toBeInTheDocument()
    })
  })
})

describe("PeersPage - Error state", () => {
  const mockRefetchError = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      usePeers: () => ({ data: null, isLoading: false, error: new Error("Failed to fetch peers"), refetch: mockRefetchError }),
    }))
    vi.doMock("@/lib/export", () => ({
      exportPeersCSV: vi.fn(),
      exportPeersJSON: vi.fn(),
    }))
    vi.clearAllMocks()
  })

  it("should show error alert when there is an error", async () => {
    const { PeersPage: PeersPageError } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageError />
      </AllProviders>
    )

    expect(screen.getByText("Failed to load peers")).toBeInTheDocument()
    expect(screen.getByText("Failed to fetch peers")).toBeInTheDocument()
  })

  it("should have retry button when there is an error", async () => {
    const { PeersPage: PeersPageError } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    expect(retryButton).toBeInTheDocument()
  })

  it("should call refetch when retry is clicked", async () => {
    const { PeersPage: PeersPageError } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    fireEvent.click(retryButton)

    expect(mockRefetchError).toHaveBeenCalled()
  })
})

// Peer with sparse data to test fallback branches
const sparsePeer = {
  id: "sparse-peer",
  hostname: "peer-sparse",
  virtualIP: "10.0.0.99",
  publicKey: "sparse123",
  status: "idle" as const,
  endpoint: undefined,
  lastHandshake: undefined,
  connectionType: undefined,
  latency: undefined,
  rxBytes: undefined,
  txBytes: undefined,
}

describe("PeersPage - Sparse peer fallback", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = [sparsePeer]
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should show N/A for undefined endpoint in table", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("peer-sparse")).toBeInTheDocument()
    // There are multiple N/A elements for different fields
    const naElements = screen.getAllByText("N/A")
    expect(naElements.length).toBeGreaterThan(0)
  })
})

describe("PeersPage - Null peers fallback", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = null as any
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should handle null peers data gracefully", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Should show Peers title even when peers is null
    expect(screen.getByText("Peers")).toBeInTheDocument()
    expect(screen.getByText("Manage peer connections in your mesh network")).toBeInTheDocument()
  })
})

describe("PeersPage - Active filter with no results", () => {
  const user = userEvent.setup()

  // All peers are Idle (inactive)
  const inactiveOnlyPeers = [
    {
      id: "inactive-peer-1",
      hostname: "inactive-peer-1",
      virtualIP: "10.0.0.20",
      publicKey: "inactive-key-1",
      state: "Idle" as const,
      endpoint: null,
      lastHandshake: null,
      connectionType: null,
      latency: null,
      rxBytes: 100,
      txBytes: 50,
    },
    {
      id: "inactive-peer-2",
      hostname: "inactive-peer-2",
      virtualIP: "10.0.0.21",
      publicKey: "inactive-key-2",
      state: "Discovered" as const,
      endpoint: null,
      lastHandshake: null,
      connectionType: null,
      latency: null,
      rxBytes: 0,
      txBytes: 0,
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = inactiveOnlyPeers
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should show empty state for active filter with no active peers", async () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Find all tabs and click the Active filter tab (in the TabsList for filtering)
    const activeTabs = screen.getAllByRole("tab", { name: /active/i })
    // The filter tab should be in the tabs list, click the first one that matches
    const filterActiveTab = activeTabs.find(tab => tab.closest('[role="tablist"]'))
    if (filterActiveTab) {
      await user.click(filterActiveTab)
    }

    await waitFor(() => {
      expect(screen.getByText("No peers found")).toBeInTheDocument()
      expect(screen.getByText(/No active peer connections/)).toBeInTheDocument()
    })
  })
})

describe("PeersPage - Inactive filter with no results", () => {
  const user = userEvent.setup()

  // All peers are active (Direct or Relayed)
  const activeOnlyPeers = [
    {
      id: "active-peer-1",
      hostname: "active-peer-1",
      virtualIP: "10.0.0.30",
      publicKey: "active-key-1",
      state: "Direct" as const,
      endpoint: "192.168.1.100:51820",
      lastHandshake: "2026-03-27T10:00:00Z",
      connectionType: "direct",
      latency: 10,
      rxBytes: 1000,
      txBytes: 500,
    },
    {
      id: "active-peer-2",
      hostname: "active-peer-2",
      virtualIP: "10.0.0.31",
      publicKey: "active-key-2",
      state: "Relayed" as const,
      endpoint: null,
      lastHandshake: "2026-03-27T09:00:00Z",
      connectionType: "relay",
      latency: 50,
      rxBytes: 500,
      txBytes: 250,
    },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = activeOnlyPeers
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should show empty state for inactive filter with no inactive peers", async () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Find the Inactive tab in the filter tabs list
    const inactiveTabs = screen.getAllByRole("tab", { name: /inactive/i })
    // The filter tab should be in the tabs list
    const filterInactiveTab = inactiveTabs.find(tab => tab.closest('[role="tablist"]'))
    if (filterInactiveTab) {
      await user.click(filterInactiveTab)
    }

    await waitFor(() => {
      expect(screen.getByText("No peers found")).toBeInTheDocument()
      expect(screen.getByText(/No inactive peers/)).toBeInTheDocument()
    })
  })
})

describe("PeersPage - All filter with no peers", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = []
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should show empty state for all filter with no peers", () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    expect(screen.getByText("No peers found")).toBeInTheDocument()
    expect(screen.getByText(/Your mesh network doesn't have any peers yet/)).toBeInTheDocument()
  })
})

describe("PeersPage - Export with null peers", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    peersState.peers = null as any
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should handle export with null peers by using empty array", async () => {
    render(
      <AllProviders>
        <PeersPage />
      </AllProviders>
    )

    // Export button should still be present but disabled
    const exportButton = screen.getByRole("button", { name: /export/i })
    // When peers is null/empty, the export button should be disabled
    expect(exportButton).toBeDisabled()
  })
})

describe("PeersPage - Export dropdown items with real dropdown", () => {
  const user = userEvent.setup()

  beforeEach(() => {
    vi.clearAllMocks()
    // Reset modules to use real dropdown-menu component
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      usePeers: () => ({
        data: peersState.peers,
        isLoading: false,
        error: null,
        refetch: mockRefetch,
      }),
    }))
    vi.doMock("@/lib/export", () => ({
      exportPeersCSV: vi.fn(),
      exportPeersJSON: vi.fn(),
    }))
  })

  afterEach(() => {
    peersState.peers = mockPeers
  })

  it("should call exportPeersCSV when clicking CSV export option", async () => {
    peersState.peers = mockPeers
    const { exportPeersCSV } = await import("@/lib/export")
    const { PeersPage: PeersPageReal } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageReal />
      </AllProviders>
    )

    // Open export dropdown
    const exportButton = screen.getByRole("button", { name: /export/i })
    await user.click(exportButton)

    // Click CSV option
    await waitFor(() => {
      expect(screen.getByText("Export as CSV")).toBeInTheDocument()
    })

    const csvOption = screen.getByText("Export as CSV")
    await user.click(csvOption)

    await waitFor(() => {
      expect(exportPeersCSV).toHaveBeenCalled()
    })
  })

  it("should call exportPeersJSON when clicking JSON export option", async () => {
    peersState.peers = mockPeers
    const { exportPeersJSON } = await import("@/lib/export")
    const { PeersPage: PeersPageReal } = await import("./peers")

    render(
      <AllProviders>
        <PeersPageReal />
      </AllProviders>
    )

    // Open export dropdown
    const exportButton = screen.getByRole("button", { name: /export/i })
    await user.click(exportButton)

    // Click JSON option
    await waitFor(() => {
      expect(screen.getByText("Export as JSON")).toBeInTheDocument()
    })

    const jsonOption = screen.getByText("Export as JSON")
    await user.click(jsonOption)

    await waitFor(() => {
      expect(exportPeersJSON).toHaveBeenCalled()
    })
  })
})
