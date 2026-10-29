import { useQuery } from "@tanstack/react-query";
import { apiGet, type Overview, type PrincipalView } from "./api";

export function usePrincipal() {
  return useQuery({ queryKey: ["principal"], queryFn: ({ signal }) => apiGet<PrincipalView>("/api/v1/me", signal) });
}

export function useOverview(enabled = true) {
  return useQuery({ queryKey: ["overview"], queryFn: ({ signal }) => apiGet<Overview>("/api/v1/overview", signal), enabled, refetchInterval: 15_000 });
}

export function hasRole(roles: string[] | undefined, ...wanted: string[]): boolean {
  return Boolean(roles?.some((role) => wanted.includes(role)));
}
