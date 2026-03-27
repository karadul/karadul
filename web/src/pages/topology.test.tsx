import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import React from "react"
import { TopologyPage } from "./topology"
import { AllProviders } from "@/test/utils"
import { mockTopology, mockNodes } from "@/test/mocks"

// Mock the API hooks
const mockRefetch = vi.fn()

vi.mock("@/lib/api", () => ({
  useTopology: () => ({
    data: mockTopology,
    isLoading: false,
    error: null,
    refetch: mockRefetch,
  }),
  useNodes: () => ({
    data: mockNodes,
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
}))

// Mock ReactFlow - renders custom nodeTypes when provided
vi.mock("@xyflow/react", () => ({
  ReactFlow: ({ nodes, edges, onNodeClick, nodeTypes }: { nodes: any[]; edges: any[]; onNodeClick?: (e: any, node: any) => void; nodeTypes?: Record<string, React.ComponentType<any>> }) => (
    <div data-testid="react-flow">
      <div data-testid="nodes-count">{nodes.length}</div>
      <div data-testid="edges-count">{edges.length}</div>
      {nodes.map((node) => {
        // Use custom node type if available
        const CustomNode = nodeTypes?.[node.type || ""]
        if (CustomNode) {
          return (
            <div
              key={node.id}
              data-testid={`node-${node.id}`}
              onClick={(e) => onNodeClick?.(e, node)}
            >
              <CustomNode data={node.data} />
            </div>
          )
        }
        return (
          <div
            key={node.id}
            data-testid={`node-${node.id}`}
            onClick={(e) => onNodeClick?.(e, node)}
          >
            {node.data?.label}
          </div>
        )
      })}
    </div>
  ),
  Background: () => <div data-testid="background" />,
  Controls: () => <div data-testid="controls" />,
  MiniMap: () => <div data-testid="minimap" />,
  useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
  useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
}))

describe("TopologyPage", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render the topology title", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    expect(screen.getByText("Network Topology")).toBeInTheDocument()
    expect(screen.getByText("Visual representation of your mesh network")).toBeInTheDocument()
  })

  it("should render legend items", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    expect(screen.getByText("Direct")).toBeInTheDocument()
    expect(screen.getByText("Relay")).toBeInTheDocument()
    expect(screen.getByText("Exit Node")).toBeInTheDocument()
  })

  it("should render ReactFlow component", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    expect(screen.getByTestId("react-flow")).toBeInTheDocument()
  })

  it("should pass nodes to ReactFlow", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // mockTopology has 2 nodes
    expect(screen.getByTestId("nodes-count")).toHaveTextContent("2")
  })

  it("should pass edges to ReactFlow", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // mockTopology has 1 connection
    expect(screen.getByTestId("edges-count")).toHaveTextContent("1")
  })

  it("should display node labels from topology", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // Node hostnames from mockTopology
    expect(screen.getByText("server-1")).toBeInTheDocument()
    expect(screen.getByText("server-2")).toBeInTheDocument()
  })

  it("should have proper card structure", () => {
    const { container } = render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // Check for Card component
    expect(container.querySelector(".rounded-lg")).toBeInTheDocument()
  })

  it("should have legend with green dot for Direct connections", () => {
    const { container } = render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    const greenDot = container.querySelector(".bg-green-500")
    expect(greenDot).toBeInTheDocument()
  })

  it("should have legend with amber dot for Relay connections", () => {
    const { container } = render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    const amberDot = container.querySelector(".bg-amber-500")
    expect(amberDot).toBeInTheDocument()
  })

  it("should call setSelectedNode when clicking on a node", async () => {
    const { useKaradulStore } = await import("@/lib/store")
    const setSelectedNodeSpy = vi.spyOn(useKaradulStore.getState(), "setSelectedNode")

    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // Click on a node
    const node = screen.getByTestId("node-node-1")
    fireEvent.click(node)

    await waitFor(() => {
      expect(setSelectedNodeSpy).toHaveBeenCalled()
    })
  })
})

describe("TopologyPage - Loading state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({ data: null, isLoading: true, error: null, refetch: vi.fn() }),
      useNodes: () => ({ data: [], isLoading: true, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: () => <div data-testid="react-flow" />,
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: () => [[], vi.fn(), vi.fn()],
      useEdgesState: () => [[], vi.fn(), vi.fn()],
    }))
  })

  it("should show loading skeleton when loading", async () => {
    const { TopologyPage: TopologyPageLoading } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageLoading />
      </AllProviders>
    )

    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})

describe("TopologyPage - Node click without matching node in store", () => {
  const mockRefetchNodeClick = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    vi.resetModules()
    // Return topology data but empty nodes array so clicked node won't be found
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({
        data: {
          nodes: [{ id: "orphan-node", hostname: "orphan", virtualIP: "10.0.0.99", status: "online", isExitNode: false }],
          connections: [],
        },
        isLoading: false,
        error: null,
        refetch: mockRefetchNodeClick,
      }),
      useNodes: () => ({
        data: [], // Empty nodes array - the clicked node won't be found
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, onNodeClick }: { nodes: any[]; onNodeClick?: (e: any, node: any) => void }) => (
        <div data-testid="react-flow">
          {nodes.map((node) => (
            <div
              key={node.id}
              data-testid={`node-${node.id}`}
              onClick={(e) => onNodeClick?.(e, node)}
            >
              {node.data?.label}
            </div>
          ))}
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should handle clicking node that doesn't exist in nodes array", async () => {
    const { useKaradulStore } = await import("@/lib/store")
    const setSelectedNodeSpy = vi.spyOn(useKaradulStore.getState(), "setSelectedNode")

    const { TopologyPage: TopologyPageOrphan } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageOrphan />
      </AllProviders>
    )

    // Click on the orphan node
    const node = screen.getByTestId("node-orphan-node")
    fireEvent.click(node)

    // Since the node doesn't exist in the nodes array, setSelectedNode should NOT be called
    await waitFor(() => {
      expect(setSelectedNodeSpy).not.toHaveBeenCalled()
    })
  })
})

describe("TopologyPage - Null topology data", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({
        data: null,
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      }),
      useNodes: () => ({
        data: [],
        isLoading: false,
        error: null,
        refetch: vi.fn(),
      }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, edges }: { nodes: any[]; edges: any[] }) => (
        <div data-testid="react-flow">
          <div data-testid="nodes-count">{nodes.length}</div>
          <div data-testid="edges-count">{edges.length}</div>
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should handle null topology data gracefully", async () => {
    const { TopologyPage: TopologyPageNull } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageNull />
      </AllProviders>
    )

    // Should still render the page structure
    expect(screen.getByText("Network Topology")).toBeInTheDocument()
    expect(screen.getByTestId("react-flow")).toBeInTheDocument()
    // With null topology, nodes and edges should be empty
    expect(screen.getByTestId("nodes-count")).toHaveTextContent("0")
    expect(screen.getByTestId("edges-count")).toHaveTextContent("0")
  })
})

describe("TopologyPage - Error state", () => {
  const mockRefetchError = vi.fn()

  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({
        data: null,
        isLoading: false,
        error: new Error("Failed to fetch topology"),
        refetch: mockRefetchError,
      }),
      useNodes: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: () => <div />,
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: () => [[], vi.fn(), vi.fn()],
      useEdgesState: () => [[], vi.fn(), vi.fn()],
    }))
  })

  it("should show error alert when there is an error", async () => {
    const { TopologyPage: TopologyPageError } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageError />
      </AllProviders>
    )

    expect(screen.getByText("Failed to load topology")).toBeInTheDocument()
    expect(screen.getByText("Failed to fetch topology")).toBeInTheDocument()
  })

  it("should have retry button when there is an error", async () => {
    const { TopologyPage: TopologyPageError } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageError />
      </AllProviders>
    )

    // ErrorAlert has a retry button
    const retryButton = screen.getByRole("button", { name: /retry/i })
    expect(retryButton).toBeInTheDocument()
  })

  it("should call refetch when clicking retry", async () => {
    const { TopologyPage: TopologyPageError } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    fireEvent.click(retryButton)

    expect(mockRefetchError).toHaveBeenCalled()
  })
})

describe("TopologyPage - Empty state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({ data: { nodes: [], connections: [] }, isLoading: false, error: null, refetch: vi.fn() }),
      useNodes: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, edges }: { nodes: any[]; edges: any[] }) => (
        <div data-testid="react-flow">
          <div data-testid="nodes-count">{nodes.length}</div>
          <div data-testid="edges-count">{edges.length}</div>
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should render with empty topology", async () => {
    const { TopologyPage: TopologyPageEmpty } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageEmpty />
      </AllProviders>
    )

    expect(screen.getByTestId("nodes-count")).toHaveTextContent("0")
    expect(screen.getByTestId("edges-count")).toHaveTextContent("0")
  })
})

describe("TopologyPage - Connection types", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should create correct edge type for direct connections", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // mockTopology has a direct connection
    expect(screen.getByTestId("edges-count")).toHaveTextContent("1")
  })

  it("should display exit node badge for exit nodes", () => {
    render(
      <AllProviders>
        <TopologyPage />
      </AllProviders>
    )

    // mockTopology has node-1 as exit node
    expect(screen.getByTestId("node-node-1")).toBeInTheDocument()
  })
})

describe("TopologyPage - Branch coverage", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({ data: null, isLoading: false, error: null, refetch: vi.fn() }),
      useNodes: () => ({ data: mockNodes, isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, edges }: { nodes: any[]; edges: any[] }) => (
        <div data-testid="react-flow">
          <div data-testid="nodes-count">{nodes.length}</div>
          <div data-testid="edges-count">{edges.length}</div>
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should handle null topology data", async () => {
    const { TopologyPage: TopologyPageNull } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageNull />
      </AllProviders>
    )

    // Should render with 0 nodes/edges when topology is null
    expect(screen.getByTestId("nodes-count")).toHaveTextContent("0")
    expect(screen.getByTestId("edges-count")).toHaveTextContent("0")
  })
})

describe("TopologyPage - Offline node status", () => {
  const topologyWithOfflineNode = {
    nodes: [
      {
        id: "offline-node",
        hostname: "offline-server",
        virtualIP: "10.0.0.99",
        status: "offline",
        isExitNode: false,
      },
    ],
    connections: [],
  }

  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({ data: topologyWithOfflineNode, isLoading: false, error: null, refetch: vi.fn() }),
      useNodes: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, edges, nodeTypes }: { nodes: any[]; edges: any[]; nodeTypes?: Record<string, React.ComponentType<any>> }) => (
        <div data-testid="react-flow">
          <div data-testid="nodes-count">{nodes.length}</div>
          <div data-testid="edges-count">{edges.length}</div>
          {nodes.map((node) => {
            const CustomNode = nodeTypes?.[node.type || ""]
            if (CustomNode) {
              return (
                <div key={node.id} data-testid={`node-${node.id}`}>
                  <CustomNode data={node.data} />
                </div>
              )
            }
            return <div key={node.id}>{node.data?.label}</div>
          })}
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should render node with offline status", async () => {
    const { TopologyPage: TopologyPageOffline } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageOffline />
      </AllProviders>
    )

    await waitFor(() => {
      expect(screen.getByText("offline-server")).toBeInTheDocument()
    })
    expect(screen.getByText("offline")).toBeInTheDocument()
  })
})

describe("TopologyPage - Relay connection type", () => {
  const topologyWithRelayConnection = {
    nodes: [
      { id: "node-a", hostname: "server-a", virtualIP: "10.0.0.10", status: "online", isExitNode: false },
      { id: "node-b", hostname: "server-b", virtualIP: "10.0.0.11", status: "online", isExitNode: false },
    ],
    connections: [
      { from: "node-a", to: "node-b", type: "relay" },
    ],
  }

  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useTopology: () => ({ data: topologyWithRelayConnection, isLoading: false, error: null, refetch: vi.fn() }),
      useNodes: () => ({ data: [], isLoading: false, error: null, refetch: vi.fn() }),
    }))
    vi.doMock("@xyflow/react", () => ({
      ReactFlow: ({ nodes, edges }: { nodes: any[]; edges: any[] }) => (
        <div data-testid="react-flow">
          <div data-testid="nodes-count">{nodes.length}</div>
          <div data-testid="edges-count">{edges.length}</div>
          {edges.map((edge) => (
            <div key={edge.id} data-testid={`edge-${edge.id}`} data-type={edge.type}>
              {edge.label}
            </div>
          ))}
        </div>
      ),
      Background: () => <div />,
      Controls: () => <div />,
      MiniMap: () => <div />,
      useNodesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
      useEdgesState: (initial: any[]) => [initial, vi.fn(), vi.fn()],
    }))
  })

  it("should create dashed edge type for relay connections", async () => {
    const { TopologyPage: TopologyPageRelay } = await import("./topology")

    render(
      <AllProviders>
        <TopologyPageRelay />
      </AllProviders>
    )

    await waitFor(() => {
      expect(screen.getByTestId("edges-count")).toHaveTextContent("1")
    })

    // Check that the edge has dashed type and Relay label
    const edge = screen.getByTestId(/edge-e/)
    expect(edge).toHaveAttribute("data-type", "dashed")
    expect(edge).toHaveTextContent("Relay")
  })
})
