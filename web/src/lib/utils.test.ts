import { describe, it, expect } from "vitest"
import { cn, formatBytes, formatDuration, formatDate } from "./utils"

describe("cn (className merger)", () => {
  it("should merge class names", () => {
    expect(cn("foo", "bar")).toBe("foo bar")
  })

  it("should handle conditional classes", () => {
    // eslint-disable-next-line no-constant-binary-expression
    expect(cn("base", true && "included", false && "excluded")).toBe("base included")
  })

  it("should handle undefined and null", () => {
    expect(cn("base", undefined, null, "end")).toBe("base end")
  })

  it("should merge tailwind classes correctly", () => {
    expect(cn("px-4 py-2", "px-6")).toBe("py-2 px-6")
  })

  it("should handle object syntax", () => {
    expect(cn({ active: true, disabled: false })).toBe("active")
  })

  it("should handle arrays", () => {
    expect(cn(["foo", "bar"])).toBe("foo bar")
  })

  it("should handle empty input", () => {
    expect(cn()).toBe("")
  })
})

describe("formatBytes", () => {
  it("should format 0 bytes", () => {
    expect(formatBytes(0)).toBe("0 Bytes")
  })

  it("should format bytes", () => {
    expect(formatBytes(500)).toBe("500 Bytes")
  })

  it("should format kilobytes", () => {
    expect(formatBytes(1024)).toBe("1 KB")
    expect(formatBytes(1536)).toBe("1.5 KB")
  })

  it("should format megabytes", () => {
    expect(formatBytes(1048576)).toBe("1 MB")
    expect(formatBytes(2621440)).toBe("2.5 MB")
  })

  it("should format gigabytes", () => {
    expect(formatBytes(1073741824)).toBe("1 GB")
  })

  it("should format terabytes", () => {
    expect(formatBytes(1099511627776)).toBe("1 TB")
  })

  it("should respect decimal parameter", () => {
    expect(formatBytes(1536, 0)).toBe("2 KB")
    expect(formatBytes(1536, 4)).toBe("1.5 KB")
  })

  it("should handle negative decimals", () => {
    expect(formatBytes(1536, -1)).toBe("2 KB")
  })
})

describe("formatDuration", () => {
  it("should format milliseconds", () => {
    expect(formatDuration(100)).toBe("100ms")
    expect(formatDuration(999)).toBe("999ms")
  })

  it("should format seconds", () => {
    expect(formatDuration(1000)).toBe("1.0s")
    expect(formatDuration(1500)).toBe("1.5s")
    expect(formatDuration(59999)).toBe("60.0s")
  })

  it("should format minutes", () => {
    expect(formatDuration(60000)).toBe("1.0m")
    expect(formatDuration(90000)).toBe("1.5m")
    expect(formatDuration(3599999)).toBe("60.0m")
  })

  it("should format hours", () => {
    expect(formatDuration(3600000)).toBe("1.0h")
    expect(formatDuration(7200000)).toBe("2.0h")
    expect(formatDuration(5400000)).toBe("1.5h")
  })
})

describe("formatDate", () => {
  it("should format ISO date string", () => {
    const date = "2026-03-26T10:00:00Z"
    const result = formatDate(date)
    expect(typeof result).toBe("string")
    expect(result.length).toBeGreaterThan(0)
  })

  it("should format Date object", () => {
    const date = new Date("2026-03-26T10:00:00Z")
    const result = formatDate(date)
    expect(typeof result).toBe("string")
    expect(result.length).toBeGreaterThan(0)
  })
})
