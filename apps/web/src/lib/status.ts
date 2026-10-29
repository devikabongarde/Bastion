export function formatPercent(value: number | null): string {
  return value === null ? "Not measured" : `${value.toFixed(1)}%`;
}

export function resultLabel(status: string): string {
  return status.replaceAll("_", " ").toLowerCase().replace(/^\w/, (letter) => letter.toUpperCase());
}

