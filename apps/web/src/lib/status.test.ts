import { describe, expect, it } from "vitest";
import { formatPercent, resultLabel } from "./status";

describe("result display", () => {
  it("does not invent a score when there are no assessable results", () => {
    expect(formatPercent(null)).toBe("Not measured");
  });

  it("formats a measured percentage to one decimal place", () => {
    expect(formatPercent(75)).toBe("75.0%");
  });

  it("renders status codes as readable labels", () => {
    expect(resultLabel("MANUAL_REQUIRED")).toBe("Manual required");
  });
});
