import { describe, it, expect } from "vitest"
import { render } from "@testing-library/react"
import { Toaster } from "./sonner"
import { AllProviders } from "@/test/utils"

describe("Sonner Toaster", () => {
  it("should render the toaster component without crashing", () => {
    const { container } = render(
      <AllProviders>
        <Toaster />
      </AllProviders>
    )

    // The Toaster component should render without errors
    expect(container.firstChild).toBeDefined()
  })

  it("should accept position prop", () => {
    const { container } = render(
      <AllProviders>
        <Toaster position="top-left" />
      </AllProviders>
    )

    // Verify component renders
    expect(container.firstChild).toBeDefined()
  })

  it("should accept richColors prop", () => {
    const { container } = render(
      <AllProviders>
        <Toaster richColors />
      </AllProviders>
    )

    // Verify component renders
    expect(container.firstChild).toBeDefined()
  })

  it("should accept expand prop", () => {
    const { container } = render(
      <AllProviders>
        <Toaster expand={true} />
      </AllProviders>
    )

    // Verify component renders
    expect(container.firstChild).toBeDefined()
  })
})
