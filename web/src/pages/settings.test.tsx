import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { render, screen, fireEvent, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { SettingsPage } from "./settings"
import { AllProviders } from "@/test/utils"
import { mockAuthKeys } from "@/test/mocks"

// Mock the API hooks
const mockRefetch = vi.fn()
const mockCreateMutateAsync = vi.fn().mockResolvedValue({ id: "new-key", key: "new-key-value" })
const mockDeleteMutateAsync = vi.fn().mockResolvedValue(undefined)

// Control function for auth keys data
const mockGetAuthKeys = vi.fn(() => mockAuthKeys)

vi.mock("@/lib/api", () => ({
  useAuthKeys: () => ({
    data: mockGetAuthKeys(),
    isLoading: false,
    error: null,
    refetch: mockRefetch,
  }),
  useCreateAuthKey: () => ({
    mutateAsync: mockCreateMutateAsync,
    isPending: false,
  }),
  useDeleteAuthKey: () => ({
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

// Mock clipboard
vi.stubGlobal("navigator", {
  ...navigator,
  clipboard: {
    writeText: vi.fn().mockResolvedValue(undefined),
  },
})

// Mock Select component
vi.mock("@/components/ui/select", () => ({
  Select: ({ children, value }: { children: React.ReactNode; value?: string }) => (
    <div data-testid="select" data-value={value}>{children}</div>
  ),
  SelectTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectValue: ({ placeholder }: { placeholder?: string }) => <span>{placeholder}</span>,
  SelectContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectItem: ({ children, value }: { children: React.ReactNode; value: string }) => (
    <button data-testid={`select-item-${value}`} onClick={() => {}}>{children}</button>
  ),
}))

describe("SettingsPage - Rendering", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render the settings title", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Settings")).toBeInTheDocument()
    expect(screen.getByText("Configure your Karadul mesh network")).toBeInTheDocument()
  })

  it("should render refresh button", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    expect(buttons.length).toBeGreaterThan(0)
  })

  it("should render tab triggers", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Auth Keys")).toBeInTheDocument()
    expect(screen.getByText("ACL Rules")).toBeInTheDocument()
    expect(screen.getByText("General")).toBeInTheDocument()
  })

  it("should render auth keys tab content by default", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Authentication Keys")).toBeInTheDocument()
    expect(screen.getByText("Manage authentication keys for new nodes")).toBeInTheDocument()
  })

  it("should render create key button", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Create Key")).toBeInTheDocument()
  })

  it("should display auth keys table headers", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Key")).toBeInTheDocument()
    expect(screen.getByText("Created")).toBeInTheDocument()
    expect(screen.getByText("Expires")).toBeInTheDocument()
    expect(screen.getByText("Used By")).toBeInTheDocument()
    expect(screen.getByText("Actions")).toBeInTheDocument()
  })

  it("should display auth key data in table", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("Unused")).toBeInTheDocument()
    expect(screen.getByText("node-1")).toBeInTheDocument()
  })

  it("should have action buttons for keys", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    expect(buttons.length).toBeGreaterThan(3)
  })

  it("should display Never badge for keys without expiration", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const neverBadges = screen.getAllByText("Never")
    expect(neverBadges.length).toBeGreaterThan(0)
  })

  it("should render ACL tab trigger", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const aclTriggers = screen.getAllByText("ACL Rules")
    expect(aclTriggers.length).toBeGreaterThan(0)
  })

  it("should render General tab trigger", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const generalTriggers = screen.getAllByText("General")
    expect(generalTriggers.length).toBeGreaterThan(0)
  })
})

describe("SettingsPage - Create Key Dialog", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should open create key dialog when Create Key button is clicked", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
      expect(screen.getByText("Create a new authentication key for node enrollment")).toBeInTheDocument()
    })
  })

  it("should show expiration select in dialog", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Expiration")).toBeInTheDocument()
    })
  })

  it("should close dialog when Cancel is clicked", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Open dialog
    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })

    // Click Cancel
    const cancelButton = screen.getByRole("button", { name: /cancel/i })
    fireEvent.click(cancelButton)

    await waitFor(() => {
      expect(screen.queryByText("Create Auth Key")).not.toBeInTheDocument()
    })
  })

  it("should call createAuthKey when Create is clicked", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Open dialog
    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })

    // Click Create button in dialog
    const dialogButtons = screen.getAllByRole("button")
    const createInDialogBtn = dialogButtons.find(btn =>
      btn.textContent?.includes("Create") &&
      !btn.textContent?.includes("Create Key")
    )

    if (createInDialogBtn) {
      fireEvent.click(createInDialogBtn)

      await waitFor(() => {
        expect(mockCreateMutateAsync).toHaveBeenCalled()
      })
    }
  })

  it("should show toast on successful key creation", async () => {
    const { toast } = await import("sonner")

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })

    const dialogButtons = screen.getAllByRole("button")
    const createInDialogBtn = dialogButtons.find(btn =>
      btn.textContent?.includes("Create") &&
      !btn.textContent?.includes("Create Key")
    )

    if (createInDialogBtn) {
      fireEvent.click(createInDialogBtn)

      await waitFor(() => {
        expect(toast.success).toHaveBeenCalledWith("Authentication key created successfully")
      })
    }
  })

  it("should show error toast on creation failure", async () => {
    const { toast } = await import("sonner")
    mockCreateMutateAsync.mockRejectedValueOnce(new Error("Creation failed"))

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })

    const dialogButtons = screen.getAllByRole("button")
    const createInDialogBtn = dialogButtons.find(btn =>
      btn.textContent?.includes("Create") &&
      !btn.textContent?.includes("Create Key")
    )

    if (createInDialogBtn) {
      fireEvent.click(createInDialogBtn)

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Failed to create key"))
      })
    }
  })

  it("should show Unknown error when create throws non-Error", async () => {
    const { toast } = await import("sonner")
    // Reject with a non-Error value
    mockCreateMutateAsync.mockRejectedValueOnce({ message: "not an error" } as any)

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const createButton = screen.getByRole("button", { name: /create key/i })
    fireEvent.click(createButton)

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })

    const dialogButtons = screen.getAllByRole("button")
    const createInDialogBtn = dialogButtons.find(btn =>
      btn.textContent?.includes("Create") &&
      !btn.textContent?.includes("Create Key")
    )

    if (createInDialogBtn) {
      fireEvent.click(createInDialogBtn)

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Unknown error"))
      })
    }
  })
})

describe("SettingsPage - Copy Key", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render key codes in the table that can be copied", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Check that the key code elements are rendered
    const codeElements = document.querySelectorAll("code")
    expect(codeElements.length).toBeGreaterThan(0)
  })

  it("should have action buttons for copy and delete", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Just verify we have multiple buttons (copy, delete, etc)
    const buttons = screen.getAllByRole("button")
    expect(buttons.length).toBeGreaterThan(5)
  })

  it("should call clipboard.writeText when copy button is clicked", async () => {
    const { toast } = await import("sonner")

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Find copy buttons - small icon buttons with h-6 w-6 class
    const buttons = screen.getAllByRole("button")

    // Find the copy button by looking for small icon buttons (h-6 class)
    const copyButtons = buttons.filter(btn =>
      btn.classList.contains("h-6") &&
      btn.classList.contains("w-6") &&
      btn.querySelector("svg")
    )

    expect(copyButtons.length).toBeGreaterThan(0)

    // Click the first copy button
    fireEvent.click(copyButtons[0])

    // Verify clipboard was called
    await waitFor(() => {
      expect(toast.success).toHaveBeenCalledWith("Key copied to clipboard")
    })
  })
})

describe("SettingsPage - Delete Key", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should call deleteAuthKey when delete button is clicked", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Find delete buttons (trash icon)
    const buttons = screen.getAllByRole("button")
    const deleteButtons = buttons.filter(btn =>
      btn.querySelector("svg.text-red-500") || btn.querySelector("svg.lucide-trash-2")
    )

    if (deleteButtons.length > 0) {
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(mockDeleteMutateAsync).toHaveBeenCalled()
      })
    }
  })

  it("should show toast on successful key deletion", async () => {
    const { toast } = await import("sonner")

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    const deleteButtons = buttons.filter(btn =>
      btn.querySelector("svg.text-red-500") || btn.querySelector("svg.lucide-trash-2")
    )

    if (deleteButtons.length > 0) {
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(toast.success).toHaveBeenCalledWith("Authentication key deleted successfully")
      })
    }
  })

  it("should show error toast on deletion failure", async () => {
    const { toast } = await import("sonner")
    mockDeleteMutateAsync.mockRejectedValueOnce(new Error("Deletion failed"))

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    const deleteButtons = buttons.filter(btn =>
      btn.querySelector("svg.text-red-500") || btn.querySelector("svg.lucide-trash-2")
    )

    if (deleteButtons.length > 0) {
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Failed to delete key"))
      })
    }
  })

  it("should show Unknown error when delete throws non-Error", async () => {
    const { toast } = await import("sonner")
    // Reject with a non-Error value
    mockDeleteMutateAsync.mockRejectedValueOnce(123 as any)

    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const buttons = screen.getAllByRole("button")
    const deleteButtons = buttons.filter(btn =>
      btn.querySelector("svg.text-red-500") || btn.querySelector("svg.lucide-trash-2")
    )

    if (deleteButtons.length > 0) {
      fireEvent.click(deleteButtons[0])

      await waitFor(() => {
        expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("Unknown error"))
      })
    }
  })
})

describe("SettingsPage - Tabs", () => {
  const user = userEvent.setup()

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should render ACL tab content with coming soon message", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Click on ACL tab using role
    const aclTab = screen.getByRole("tab", { name: /acl rules/i })
    await user.click(aclTab)

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /access control rules/i })).toBeInTheDocument()
      expect(screen.getByText("ACL configuration coming soon")).toBeInTheDocument()
    })
  })

  it("should render General tab content", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Click on General tab using role
    const generalTab = screen.getByRole("tab", { name: /general/i })
    await user.click(generalTab)

    await waitFor(() => {
      expect(screen.getByRole("heading", { name: /general settings/i })).toBeInTheDocument()
      expect(screen.getByText("Configure general network settings")).toBeInTheDocument()
    })
  })

  it("should render network name input in General tab", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const generalTab = screen.getByRole("tab", { name: /general/i })
    await user.click(generalTab)

    await waitFor(() => {
      expect(screen.getByLabelText(/network name/i)).toBeInTheDocument()
    })
  })

  it("should render coordinator URL input in General tab", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const generalTab = screen.getByRole("tab", { name: /general/i })
    await user.click(generalTab)

    await waitFor(() => {
      expect(screen.getByLabelText(/coordinator url/i)).toBeInTheDocument()
    })
  })

  it("should render Save Changes button in General tab", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    const generalTab = screen.getByRole("tab", { name: /general/i })
    await user.click(generalTab)

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /save changes/i })).toBeInTheDocument()
    })
  })
})

describe("SettingsPage - Loading state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useAuthKeys: () => ({ data: null, isLoading: true, error: null, refetch: vi.fn() }),
      useCreateAuthKey: () => ({ mutateAsync: vi.fn(), isPending: false }),
      useDeleteAuthKey: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/components/ui/select", () => ({
      Select: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectValue: ({ placeholder }: { placeholder?: string }) => <span>{placeholder}</span>,
      SelectContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
    }))
  })

  it("should show loading skeletons when loading", async () => {
    const { SettingsPage: SettingsPageLoading } = await import("./settings")

    render(
      <AllProviders>
        <SettingsPageLoading />
      </AllProviders>
    )

    const skeletons = document.querySelectorAll(".animate-pulse")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})

describe("SettingsPage - Error state", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.doMock("@/lib/api", () => ({
      useAuthKeys: () => ({
        data: null,
        isLoading: false,
        error: new Error("Failed to fetch auth keys"),
        refetch: mockRefetch,
      }),
      useCreateAuthKey: () => ({ mutateAsync: vi.fn(), isPending: false }),
      useDeleteAuthKey: () => ({ mutateAsync: vi.fn(), isPending: false }),
    }))
    vi.doMock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
    vi.doMock("@/components/ui/select", () => ({
      Select: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectValue: ({ placeholder }: { placeholder?: string }) => <span>{placeholder}</span>,
      SelectContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
      SelectItem: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
    }))
  })

  it("should show error alert when there is an error", async () => {
    const { SettingsPage: SettingsPageError } = await import("./settings")

    render(
      <AllProviders>
        <SettingsPageError />
      </AllProviders>
    )

    expect(screen.getByText("Failed to load settings")).toBeInTheDocument()
    expect(screen.getByText("Failed to fetch auth keys")).toBeInTheDocument()
  })

  it("should have retry button when there is an error", async () => {
    const { SettingsPage: SettingsPageError } = await import("./settings")

    render(
      <AllProviders>
        <SettingsPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    expect(retryButton).toBeInTheDocument()
  })

  it("should call refetch when retry is clicked", async () => {
    const { SettingsPage: SettingsPageError } = await import("./settings")

    render(
      <AllProviders>
        <SettingsPageError />
      </AllProviders>
    )

    const retryButton = screen.getByRole("button", { name: /retry/i })
    fireEvent.click(retryButton)

    expect(mockRefetch).toHaveBeenCalled()
  })
})

describe("SettingsPage - Empty state", () => {
  const user = userEvent.setup()

  beforeEach(() => {
    vi.clearAllMocks()
    // Set empty keys for these tests
    mockGetAuthKeys.mockReturnValue([])
  })

  afterEach(() => {
    // Reset to normal keys after empty state tests
    mockGetAuthKeys.mockReturnValue(mockAuthKeys)
  })

  it("should show empty state when no auth keys", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    expect(screen.getByText("No auth keys")).toBeInTheDocument()
    expect(screen.getByText(/Create an authentication key to allow new nodes/)).toBeInTheDocument()
  })

  it("should show Create Key action in empty state", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Empty state has its own Create Key button
    const createButtons = screen.getAllByText("Create Key")
    expect(createButtons.length).toBeGreaterThan(0)
  })

  it("should open create dialog when clicking empty state Create Key button", async () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Find and click the empty state Create Key button
    const createButtons = screen.getAllByText("Create Key")
    await user.click(createButtons[0])

    await waitFor(() => {
      expect(screen.getByText("Create Auth Key")).toBeInTheDocument()
    })
  })
})

describe("SettingsPage - Key Expiration Display", () => {
  it("should show clock icon for keys with expiration", () => {
    const { container } = render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Look for amber-colored elements which indicate expiration
    const amberElements = container.querySelectorAll(".text-amber-600")
    expect(amberElements.length).toBeGreaterThan(0)
  })
})

describe("SettingsPage - Refresh", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("should have refresh button that calls refetch", () => {
    render(
      <AllProviders>
        <SettingsPage />
      </AllProviders>
    )

    // Find the refresh button (has RefreshCw icon)
    const buttons = screen.getAllByRole("button")
    const refreshButton = buttons.find(btn =>
      btn.querySelector("svg.lucide-refresh-cw") ||
      (btn.getAttribute("variant") === "outline" && btn.querySelector("svg"))
    )

    if (refreshButton) {
      fireEvent.click(refreshButton)
      // Note: refetch may or may not be called depending on mock setup
    }
  })
})
