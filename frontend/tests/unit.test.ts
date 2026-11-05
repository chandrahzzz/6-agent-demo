import { describe, expect, it } from "vitest";

import { toneOf } from "../components/status";
import { bytes, ms, num, utc } from "../lib/format";

describe("status tones carry meaning only", () => {
  it("maps verdicts to the spec's colours", () => {
    expect(toneOf("STILL_EXPOSED")).toBe("critical");
    expect(toneOf("PARTIALLY_FIXED")).toBe("warning");
    expect(toneOf("VERIFIED_FIXED")).toBe("ok");
    expect(toneOf("UNVERIFIED")).toBe("unverified");
    expect(toneOf("LIKELY_EXFILTRATED")).toBe("critical");
    expect(toneOf("Critical")).toBe("critical");
    expect(toneOf("High")).toBe("warning");
  });
  it("treats a missing verdict as unverified, never as fixed", () => {
    expect(toneOf(null)).toBe("unverified");
    expect(toneOf(undefined)).toBe("unverified");
  });
  it("a genuine denial is good news, an accessible probe is not", () => {
    expect(toneOf("DENIED")).toBe("ok");
    expect(toneOf("ACCESSIBLE")).toBe("critical");
    expect(toneOf("DNS_FAILURE")).toBe("unverified");
  });
});

describe("formatters", () => {
  it("formats numbers, bytes and durations", () => {
    expect(num(5000)).toBe("5,000");
    expect(num(null)).toBe("—");
    expect(bytes(622938)).toBe("608.3 KB");
    expect(ms(950)).toBe("950 ms");
    expect(ms(35693.3)).toBe("35.7 s");
  });
  it("renders UTC for audit display", () => {
    expect(utc("2026-11-05T09:15:12.000Z")).toBe("2026-11-05 09:15:12Z");
    expect(utc("2026-11-05T09:15:12.000Z", false)).toBe("09:15:12Z");
  });
});
