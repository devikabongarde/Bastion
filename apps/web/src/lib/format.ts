export function pct(value: number | null | undefined, digits = 0): string {
  return value === null || value === undefined ? "—" : `${value.toFixed(digits)}%`;
}

export function when(value: string | null | undefined): string {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function ago(value: string | null | undefined): string {
  if (!value) return "never";
  const seconds = Math.max(1, Math.round((Date.now() - new Date(value).getTime()) / 1000));
  const units: Array<[number, string]> = [[86400, "d"], [3600, "h"], [60, "m"]];
  for (const [size, label] of units) if (seconds >= size) return `${Math.floor(seconds / size)}${label} ago`;
  return `${seconds}s ago`;
}

export function shortKey(controlKey: string): string {
  return controlKey.split(".").slice(-1)[0]!.replaceAll("_", " ");
}

export function label(text: string): string {
  return text.replaceAll("_", " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

export function show(value: unknown): string {
  if (value === null || value === undefined) return "not observed";
  return typeof value === "string" ? value : JSON.stringify(value);
}

/** Show the observed value of the fact a control asserts on, not the whole fact bundle. */
export function observed(actual: unknown, expectedFact: unknown): string {
  if (actual && typeof actual === "object" && !Array.isArray(actual)) {
    const facts = actual as Record<string, unknown>;
    if (typeof expectedFact === "string" && expectedFact in facts) return show(facts[expectedFact]);
    const entries = Object.entries(facts).filter(([key]) => key !== "platform.family");
    if (entries.length === 1) return show(entries[0]![1]);
    return entries.map(([key, value]) => `${key}=${show(value)}`).join("\n");
  }
  return show(actual);
}
