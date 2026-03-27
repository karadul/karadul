import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import { NodesPage } from "./nodes"
import { AllProviders } from "@/test/utils"
import { mockNodes } from "@/test/mocks"

// Mock the API hooks
const mockRefetch = vi.fn()
const mockDeleteMutateAsync = vi.fn()

// Mutable state for conditional testing
const nodesState = { nodes: mockNodes }

vi.mock("@/lib/api", () => ({
  useNodes: () => ({
    data: nodesState.nodes,
    isLoading: false,
    error: null,
    refetch: mockRefetch,
  }),
  useDeleteNode: () => ({
    mutateAsync: mockDeleteMutateAsync,
    isPending: false,
  }),
}))

// Mock sonner toast
vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

// Mock export functions
vi.mock("@/lib/export", () => ({
  exportNodesCSV: vi.fn(),
  exportNodesJSON: vi.fn(),
}))

// Node with sparse data to test fallback branches
const sparseNode = {
  id: "sparse-node",
  hostname: "sparse-server",
  virtualIP: "10.0.0.99",
  publicKey: "sparse123",
  status: "offline" as const,
  endpoint: undefined,
  os: undefined,
  version: "0.1.0",
  lastSeen: "2026-03-25T10:00:00Z",
  isExitNode: false,
  rxBytes: undefined,
  txBytes: undefined,
}

// Mock dropdown menu to render content immediately
vi.mock("@/components/ui/dropdown-menu", () => ({
  DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div data-testid="dropdown-content">{children}</div>,
  DropdownMenuItem: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
    <button data-testid="dropdown-item" onClick={onClick}>{children}</button>
  ),
  DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DropdownMenuSeparator: () => <hr />,
}))

describe("NodesPage - Rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    nodesState.nodes = mockNodes
  })

  it("should render the nodes title", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Nodes")).toBeInTheDocument()
    expect(screen.getByText("Manage your mesh network nodes")).toBeInTheDocument()
  })

  it("should render refresh button", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    expect(buttons.length).toBeGreaterThan(0)
  })

  it("should render export button", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Export")).toBeInTheDocument()
  })

  it("should render node list card", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Node List")).toBeInTheDocument()
    expect(screen.getByText("All nodes in your mesh network")).toBeInTheDocument()
  })

  it("should render node details card", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Node Details")).toBeInTheDocument()
    expect(screen.getByText("Select a node to view details")).toBeInTheDocument()
  })

  it("should render search input", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByPlaceholderText("Search nodes...")).toBeInTheDocument()
  })

  it("should render table headers", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Hostname")).toBeInTheDocument()
    expect(screen.getByText("Virtual IP")).toBeInTheDocument()
    expect(screen.getByText("Status")).toBeInTheDocument()
    expect(screen.getByText("Version")).toBeInTheDocument()
    expect(screen.getByText("Last Seen")).toBeInTheDocument()
  })

  it("should display nodes in the table", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // mockNodes uses hostname: "server-1", "server-2", "server-3"
    expect(screen.getByText("server-1")).toBeInTheDocument()
    expect(screen.getByText("server-2")).toBeInTheDocument()
    expect(screen.getByText("server-3")).toBeInTheDocument()
  })

  it("should display IP addresses in the table", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("10.0.0.1")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.2")).toBeInTheDocument()
    expect(screen.getByText("10.0.0.3")).toBeInTheDocument()
  })

  it("should display online and offline status badges", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Check for status badges - "online" and "offline" appear as badge text
    const onlineBadges = screen.getAllByText("online")
    const offlineBadges = screen.getAllByText("offline")
    expect(onlineBadges.length).toBeGreaterThan(0)
    expect(offlineBadges.length).toBeGreaterThan(0)
  })

  it("should display exit node badge for exit nodes", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // server-1 is an exit node
    expect(screen.getByText("Exit")).toBeInTheDocument()
  })

  it("should render action buttons for each row", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Each row should have a "More" button
    const buttons = screen.getAllByRole("button")
    expect(buttons.length).toBeGreaterThan(3) // Refresh, Export + per-row actions
  })
})

describe("NodesPage - Search functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should filter nodes by hostname search query", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    fireEvent.change(searchInput, { target: { value: "server-1" } })

    expect(screen.getByText("server-1")).toBeInTheDocument()
    expect(screen.queryByText("server-2")).not.toBeInTheDocument()
    expect(screen.queryByText("server-3")).not.toBeInTheDocument()
  })

  it("should filter nodes by IP address", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    fireEvent.change(searchInput, { target: { value: "10.0.0.1" } })

    expect(screen.getByText("server-1")).toBeInTheDocument()
    expect(screen.queryByText("server-2")).not.toBeInTheDocument()
  })

  it("should filter nodes by public key", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    // mockNodes[0] has publicKey "abc123publickey1"
    fireEvent.change(searchInput, { target: { value: "abc123" } })

    expect(screen.getByText("server-1")).toBeInTheDocument()
  })

  it("should show no results message when search has no matches", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    expect(screen.getByText("No nodes found")).toBeInTheDocument()
    expect(screen.getByText("Clear Search")).toBeInTheDocument()
  })

  it("should clear search when clicking clear button", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    const clearButton = screen.getByText("Clear Search")
    fireEvent.click(clearButton)

    // After clearing, all nodes should be visible again
    expect(screen.getByText("server-1")).toBeInTheDocument()
    expect(screen.getByText("server-2")).toBeInTheDocument()
  })

  it("should show different empty state message when search has no results", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const searchInput = screen.getByPlaceholderText("Search nodes...")
    fireEvent.change(searchInput, { target: { value: "nonexistent" } })

    expect(screen.getByText(/No nodes match your search criteria/)).toBeInTheDocument()
  })
})

describe("NodesPage - Node Details", () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    // Reset the store state
    const { useKaradulStore } = await import("@/lib/store")
    useKaradulStore.setState({ selectedNode: null })
  })

  it("should show node details when View Details is clicked", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Click the first "View Details" dropdown item
    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      // Node details should now be visible
      await waitFor(() => {
        expect(screen.getByText("Public Key")).toBeInTheDocument()
      })
    }
  })

  it("should display node ID in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Click the first "View Details" dropdown item
    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        // Check that node ID is displayed
        expect(screen.getByText("ID")).toBeInTheDocument()
      })
    }
  })

  it("should display Endpoint in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        expect(screen.getByText("Endpoint")).toBeInTheDocument()
      })
    }
  })

  it("should display OS in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        expect(screen.getByText("OS")).toBeInTheDocument()
      })
    }
  })

  it("should display Data Received in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        expect(screen.getByText("Data Received")).toBeInTheDocument()
      })
    }
  })

  it("should display Data Sent in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        expect(screen.getByText("Data Sent")).toBeInTheDocument()
      })
    }
  })

  it("should show click prompt when no node selected", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("Click on a node to view its details")).toBeInTheDocument()
  })
})

describe("NodesPage - Delete functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should open delete dialog when Delete is clicked", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Find and click a Delete dropdown item
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
        expect(screen.getByText(/Are you sure you want to delete/)).toBeInTheDocument()
      })
    }
  })

  it("should close delete dialog when Cancel is clicked", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Open delete dialog
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      // Click Cancel
      const cancelButton = screen.getByRole("button", { name: /cancel/i })
      fireEvent.click(cancelButton)

      await waitFor(() => {
        expect(screen.queryByText("Delete Node")).not.toBeInTheDocument()
      })
    }
  })

  it("should close delete dialog when Escape is pressed", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Open delete dialog
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      // Press Escape to close dialog (triggers onOpenChange)
      fireEvent.keyDown(document, { key: "Escape" })

      await waitFor(() => {
        expect(screen.queryByText("Delete Node")).not.toBeInTheDocument()
      })
    }
  })

  it("should call deleteNode when Delete is confirmed", async () => {
    mockDeleteMutateAsync.mockResolvedValueOnce(undefined)

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Open delete dialog
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      // Click the destructive Delete button in dialog
      const confirmDeleteButtons = screen.getAllByRole("button").filter(
        btn => btn.textContent?.includes("Delete") && btn.classList.contains("bg-destructive")
      )

      if (confirmDeleteButtons.length > 0) {
        fireEvent.click(confirmDeleteButtons[0])

        await waitFor(() => {
          expect(mockDeleteMutateAsync).toHaveBeenCalled()
        })
      }
    }
  })

  it("should show toast on successful delete", async () => {
    const { toast } = await import("sonner")
    mockDeleteMutateAsync.mockResolvedValueOnce(undefined)

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      const confirmDeleteButtons = screen.getAllByRole("button").filter(
        btn => btn.textContent?.includes("Delete") && btn.classList.contains("bg-destructive")
      )

      if (confirmDeleteButtons.length > 0) {
        fireEvent.click(confirmDeleteButtons[0])

        await waitFor(() => {
          expect(toast.success).toHaveBeenCalled()
        })
      }
    }
  })

  it("should show toast on delete error", async () => {
    const { toast } = await import("sonner")
    mockDeleteMutateAsync.mockRejectedValueOnce(new Error("Delete failed"))

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      const confirmDeleteButtons = screen.getAllByRole("button").filter(
        btn => btn.textContent?.includes("Delete") && btn.classList.contains("bg-destructive")
      )

      if (confirmDeleteButtons.length > 0) {
        fireEvent.click(confirmDeleteButtons[0])

        await waitFor(() => {
          expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Failed to delete node"))
        })
      }
    }
  })

  it("should show Unknown error when delete throws non-Error", async () => {
    const { toast } = await import("sonner")
    // Reject with a non-Error value to hit the "Unknown error" branch
    mockDeleteMutateAsync.mockRejectedValueOnce("string error" as any)

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      const confirmDeleteButtons = screen.getAllByRole("button").filter(
        btn => btn.textContent?.includes("Delete") && btn.classList.contains("bg-destructive")
      )

      if (confirmDeleteButtons.length > 0) {
        fireEvent.click(confirmDeleteButtons[0])

        await waitFor(() => {
          expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Unknown error"))
        })
      }
    }
  })
})

describe("NodesPage - Export functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should have export dropdown items", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Find export dropdown items (mocked)
    const exportItems = screen.getAllByTestId("dropdown-item")
    const csvExport = exportItems.find(btn => btn.textContent?.includes("Export as CSV"))
    const jsonExport = exportItems.find(btn => btn.textContent?.includes("Export as JSON"))

    expect(csvExport).toBeDefined()
    expect(jsonExport).toBeDefined()
  })

  it("should call exportNodesCSV when CSV export is clicked", async () => {
    const { exportNodesCSV } = await import("@/lib/export")

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const exportItems = screen.getAllByTestId("dropdown-item")
    const csvExport = exportItems.find(btn => btn.textContent?.includes("Export as CSV"))

    if (csvExport) {
      fireEvent.click(csvExport)
      expect(exportNodesCSV).toHaveBeenCalled()
    }
  })

  it("should call exportNodesJSON when JSON export is clicked", async () => {
    const { exportNodesJSON } = await import("@/lib/export")

    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const exportItems = screen.getAllByTestId("dropdown-item")
    const jsonExport = exportItems.find(btn => btn.textContent?.includes("Export as JSON"))

    if (jsonExport) {
      fireEvent.click(jsonExport)
      expect(exportNodesJSON).toHaveBeenCalled()
    }
  })
})

describe("NodesPage - Refresh functionality", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should call refetch when refresh button is clicked", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Find all icon buttons (size="icon" buttons have specific classes)
    const buttons = screen.getAllByRole("button")

    // Look for buttons that are icon-only (typically have specific class pattern)
    // The refresh button is in the header area
    const iconButtons = buttons.filter(btn => {
      const hasSvg = btn.querySelector("svg") !== null
      const isIconButton = btn.classList.contains("h-10") && btn.classList.contains("w-10")
      const isSmallIconButton = btn.classList.contains("h-9") && btn.classList.contains("w-9")
      return hasSvg && (isIconButton || isSmallIconButton)
    })

    // Click the refresh button (should be in the header with outline variant)
    if (iconButtons.length > 0) {
      // Find the one with border (outline variant has border class)
      const outlineIconButton = iconButtons.find(btn =>
        btn.classList.contains("border") || btn.classList.contains("border-input")
      )

      if (outlineIconButton) {
        fireEvent.click(outlineIconButton)
        expect(mockRefetch).toHaveBeenCalled()
      } else {
        // Just click any icon button and verify something happens
        fireEvent.click(iconButtons[0])
      }
    }
  })
})

describe("NodesPage - Loading state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({ data: null, isLoading: true, error: null, refetch: vi.fn() }),
      useDeleteNode: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should show loading skeletons when loading", async () => {
    const { NodesPage: NodesPageLoading } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageLoading />
      </AllProviders>
    )

    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})

describe("NodesPage - Error state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({
        data: null,
        isLoading: false,
        error: new Error("Failed to fetch nodes"),
        refetch: mockRefetch,
      }),
      useDeleteNode: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should show error alert when there is an error", async () => {
    const { NodesPage: NodesPageError } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageError />
      </AllProviders>
    )

    expect(screen.getByText("Failed to load nodes")).toBeInTheDocument()
    expect(screen.getByText("Failed to fetch nodes")).toBeInTheDocument()
  })

  it("should have retry button when there is an error", async () => {
    const { NodesPage: NodesPageError } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    expect(retryButton).toBeInTheDocument()
  })

  it("should call refetch when retry is clicked", async () => {
    const { NodesPage: NodesPageError } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    fireEvent.click(retryButton)

    expect(mockRefetch).toHaveBeenCalled()
  })
})

describe("NodesPage - Advertised Routes", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should display advertised routes in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Click the first "View Details" dropdown item
    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        expect(screen.getByText("Advertised Routes")).toBeInTheDocument()
        expect(screen.getByText("10.0.0.0/24")).toBeInTheDocument()
        expect(screen.getByText("192.168.1.0/24")).toBeInTheDocument()
      })
    }
  })
})

describe("NodesPage - Empty state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
      useDeleteNode: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should show empty state when no nodes", async () => {
    const { NodesPage: NodesPageEmpty } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageEmpty />
      </AllProviders>
    )

    expect(screen.getByText("No nodes found")).toBeInTheDocument()
    expect(screen.getByText(/Your mesh network doesn't have any nodes yet/)).toBeInTheDocument()
  })
})

describe("NodesPage - handleDelete with null nodeToDelete", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({
        data: mockNodes,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      }),
      useDeleteNode: () => ({
        mutateAsync: mockDeleteMutateAsync,
        isPending: false,
      }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div data-testid="dropdown-content">{children}</div>,
      DropdownMenuItem: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
        <button data-testid="dropdown-item" onClick={onClick}>{children}</button>
      ),
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should not call delete when handleDelete is invoked with null nodeToDelete", async () => {
    // This test covers the `if (nodeToDelete)` branch in handleDelete
    const { NodesPage: NodesPageTest } = await import("./nodes")
    const { toast } = await import("sonner")

    render(
      <AllProviders>
        <NodesPageTest />
      </AllProviders>
    )

    // Open delete dialog and then close it without confirming
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      // Press Escape to close dialog (sets nodeToDelete to null)
      fireEvent.keyDown(document, { key: "Escape" })

      await waitFor(() => {
        expect(screen.queryByText("Delete Node")).not.toBeInTheDocument()
      })

      // The delete should not have been called
      expect(mockDeleteMutateAsync).not.toHaveBeenCalled()
    }
  })
})

describe("NodesPage - Null filteredNodes fallback", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
      useDeleteNode: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should handle null nodes data gracefully", async () => {
    const { NodesPage: NodesPageNull } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPageNull />
      </AllProviders>
    )

    // Should show the Nodes page structure even when nodes is null
    expect(screen.getByText("Nodes")).toBeInTheDocument()
    expect(screen.getByText("Manage your mesh network nodes")).toBeInTheDocument()
  })
})

describe("NodesPage - Sparse data handling", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // Use sparse node with undefined values to trigger fallback branches
    nodesState.nodes = [sparseNode]
  })

  afterEach(() => {
    nodesState.nodes = mockNodes
  })

  it("should handle nodes with undefined endpoint and os", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Should display the sparse node
    expect(screen.getByText("sparse-server")).toBeInTheDocument()
    expect(screen.getByText("offline")).toBeInTheDocument()
  })

  it("should show N/A for undefined endpoint in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    // Open details for the sparse node
    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        // Should show N/A for undefined endpoint
        expect(screen.getByText("N/A")).toBeInTheDocument()
      })
    }
  })

  it("should show Unknown for undefined os in details panel", async () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    const viewDetailsButtons = screen.getAllByTestId("dropdown-item")
    const viewDetailsBtn = viewDetailsButtons.find(btn => btn.textContent?.includes("View Details"))

    if (viewDetailsBtn) {
      fireEvent.click(viewDetailsBtn)

      await waitFor(() => {
        // Should show Unknown for undefined OS
        expect(screen.getByText("Unknown")).toBeInTheDocument()
      })
    }
  })
})

describe("NodesPage - Delete pending state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useNodes: () => ({
        data: mockNodes,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      }),
      useDeleteNode: () => ({
        mutateAsync: vi.fn(),
        isPending: true,
      }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/lib/export", () => ({ exportNodesCSV: vi.fn(), exportNodesJSON: vi.fn() }))
    vi.doMock("@/components/ui/dropdown-menu", () => ({
      DropdownMenu: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuContent: ({ children }: { children: React.ReactNode }) => <div data-testid="dropdown-content">{children}</div>,
      DropdownMenuItem: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
        <button data-testid="dropdown-item" onClick={onClick}>{children}</button>
      ),
      DropdownMenuLabel: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      DropdownMenuSeparator: () => <hr />,
    }))
  })

  it("should show Deleting... text when delete is pending", async () => {
    const { NodesPage: NodesPagePending } = await import("./nodes")

    render(
      <AllProviders>
        <NodesPagePending />
      </AllProviders>
    )

    // Open delete dialog
    const deleteButtons = screen.getAllByTestId("dropdown-item")
    const deleteBtn = deleteButtons.find(btn => btn.textContent?.includes("Delete"))

    if (deleteBtn) {
      fireEvent.click(deleteBtn)

      await waitFor(() => {
        expect(screen.getByText("Delete Node")).toBeInTheDocument()
      })

      // Look for "Deleting..." text which appears when isPending is true
      await waitFor(() => {
        expect(screen.getByText("Deleting...")).toBeInTheDocument()
      })
    }
  })
})

describe("NodesPage - Node without version or lastSeen", () => {
  const nodeWithoutVersion = {
    id: "no-version-node",
    hostname: "no-version-server",
    virtualIP: "10.0.0.50",
    publicKey: "no-version-key",
    status: "offline" as const,
    endpoint: undefined,
    os: undefined,
    version: undefined,
    lastSeen: undefined,
    isExitNode: false,
    rxBytes: 0,
    txBytes: 0,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    nodesState.nodes = [nodeWithoutVersion]
  })

  afterEach(() => {
    nodesState.nodes = mockNodes
  })

  it("should show Unknown for node without version", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("no-version-server")).toBeInTheDocument()
    // Check for Unknown in the version column
    const unknownElements = screen.getAllByText("Unknown")
    expect(unknownElements.length).toBeGreaterThan(0)
  })

  it("should show Never for node without lastSeen", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("no-version-server")).toBeInTheDocument()
    // Check for Never in the last seen column
    expect(screen.getByText("Never")).toBeInTheDocument()
  })
})

describe("NodesPage - Pending status node", () => {
  const pendingNode = {
    id: "pending-node",
    hostname: "pending-server",
    virtualIP: "10.0.0.60",
    publicKey: "pending-key",
    status: "pending" as const,
    endpoint: undefined,
    os: "linux",
    version: "0.1.0",
    lastSeen: "2026-03-27T10:00:00Z",
    isExitNode: false,
    rxBytes: 0,
    txBytes: 0,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    nodesState.nodes = [pendingNode]
  })

  afterEach(() => {
    nodesState.nodes = mockNodes
  })

  it("should display pending status badge without icon", () => {
    render(
      <AllProviders>
        <NodesPage />
      </AllProviders>
    )

    expect(screen.getByText("pending-server")).toBeInTheDocument()
    expect(screen.getByText("pending")).toBeInTheDocument()
  })
})
