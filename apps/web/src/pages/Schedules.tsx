import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type PolicyOverview } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { when } from "../lib/format";
import { Chip, Empty, ErrorNotice, PageHeading, Skeleton, useToast } from "../components/ui";

interface ScheduleItem {
  id: string; name: string; site_name: string; cron: string; timezone: string; enabled: boolean;
  last_occurrence_at: string | null; next_occurrence_at: string | null;
}

export default function Schedules() {
  const cache = useQueryClient();
  const toast = useToast();
  const principal = usePrincipal();
  const list = useQuery({ queryKey: ["schedules"], queryFn: ({ signal }) => apiGet<{ items: ScheduleItem[]; sites: Array<{ id: string; name: string }> }>("/api/v1/schedules", signal) });
  const policies = useQuery({ queryKey: ["policy-overview"], queryFn: ({ signal }) => apiGet<PolicyOverview>("/api/v1/policy-overview", signal) });
  const published = policies.data?.policies.find((p) => p.state === "published");
  const [cron, setCron] = useState("0 2 * * *");
  const refresh = () => cache.invalidateQueries({ queryKey: ["schedules"] });
  const create = useMutation({
    mutationFn: (body: Record<string, string>) => apiWrite("/api/v1/schedules", { ...body, policy_id: published?.id, overlap_policy: "skip" }),
    onSuccess: async () => { toast("ok", "Schedule created"); await refresh(); },
    onError: (e) => toast("err", e.message),
  });
  const toggle = useMutation({
    mutationFn: (id: string) => apiWrite(`/api/v1/schedules/${id}/toggle`),
    onSuccess: refresh,
    onError: (e) => toast("err", e.message),
  });
  const canEdit = hasRole(principal.data?.roles, "scan_operator", "platform_admin");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    create.mutate({ name: String(form.get("name")), site_id: String(form.get("site")), cron, timezone: String(form.get("tz")) });
  }
  return (
    <>
      <PageHeading title="Schedules" description="Recurring live collection with explicit IANA time zones. Each occurrence runs once, even if the scheduler ticks repeatedly." />
      <div className="grid two">
        <section className="panel">
          <div className="panel-head"><h2>Schedules</h2></div>
          {list.isPending && <Skeleton rows={3} />}
          {list.isError && <ErrorNotice error={list.error} />}
          {list.isSuccess && list.data.items.length === 0 && <Empty icon="clock" title="No schedules">Create one to assess a site on a recurring basis.</Empty>}
          {list.isSuccess && list.data.items.length > 0 && (
            <div className="table-wrap"><table>
              <thead><tr><th scope="col">Name</th><th scope="col">Cron</th><th scope="col">Next run</th><th scope="col">State</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{list.data.items.map((s) => (
                <tr key={s.id}>
                  <th scope="row">{s.name}<span className="cell-sub">{s.site_name}</span></th>
                  <td><code>{s.cron}</code><span className="cell-sub">{s.timezone}</span></td>
                  <td>{when(s.next_occurrence_at)}<span className="cell-sub">last: {when(s.last_occurrence_at)}</span></td>
                  <td><Chip tone={s.enabled ? "ok" : "never"}>{s.enabled ? "Enabled" : "Paused"}</Chip></td>
                  <td className="num">{canEdit && <button className="btn sm" onClick={() => toggle.mutate(s.id)}>{s.enabled ? "Pause" : "Resume"}</button>}</td>
                </tr>))}
              </tbody>
            </table></div>
          )}
          <p className="quiet" style={{ marginTop: 14 }}>Scheduled runs collect from live adapters only. Offline-import and fixture assets are skipped and the occurrence is recorded as skipped.</p>
        </section>
        <section className="panel">
          <div className="panel-head"><h2>New schedule</h2></div>
          {canEdit ? (
            <form className="form-grid" onSubmit={submit}>
              <label className="field">Name<input name="name" required maxLength={255} placeholder="Nightly HQ audit" /></label>
              <label className="field">Site<select name="site" required>{list.data?.sites.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>
              <label className="field">Cron (minute hour day month weekday)<input value={cron} onChange={(e) => setCron(e.target.value)} className="mono" required /></label>
              <label className="field">Time zone<input name="tz" defaultValue="UTC" required placeholder="Europe/Berlin" /></label>
              <button className="btn primary" disabled={create.isPending || !published}>{create.isPending ? "Creating…" : "Create schedule"}</button>
            </form>
          ) : <Empty icon="lock" title="Read-only access">Your role cannot create schedules.</Empty>}
        </section>
      </div>
    </>
  );
}
