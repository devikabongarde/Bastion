import { useQuery } from "@tanstack/react-query";
import { apiGet, type Overview, type Page, type PolicySummary, type PrincipalView } from "./api";

export function usePrincipal() {
  return useQuery({ queryKey: ["principal"], queryFn: ({ signal }) => apiGet<PrincipalView>("/api/v1/me", signal) });
}

export function useOverview(enabled = true) {
  return useQuery({ queryKey: ["overview"], queryFn: ({ signal }) => apiGet<Overview>("/api/v1/overview", signal), enabled, refetchInterval: 15_000 });
}

export function hasRole(roles: string[] | undefined, ...wanted: string[]): boolean {
  return Boolean(roles?.some((role) => wanted.includes(role)));
}

/** The published policy to assess against: the one covering the most platforms, newest first. */
export function useActivePolicy() {
  return useQuery({
    queryKey: ["policies", "active"],
    queryFn: async ({ signal }) => {
      const page = await apiGet<Page<PolicySummary>>("/api/v1/policies?limit=100", signal);
      const published = page.items.filter((p) => p.state === "published");
      published.sort(
        (a, b) =>
          b.rule_packs.length - a.rule_packs.length ||
          (b.published_at ?? "").localeCompare(a.published_at ?? "")
      );
      return published[0] ?? null;
    },
    staleTime: 60_000,
  });
}
