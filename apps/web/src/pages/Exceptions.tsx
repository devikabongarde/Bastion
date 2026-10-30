import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, apiWrite, type ExceptionItem } from "../lib/api";
import { hasRole, usePrincipal } from "../lib/hooks";
import { shortKey, when } from "../lib/format";
import { Empty, ErrorNotice, PageHeading, Skeleton, StateChip, useToast } from "../components/ui";

export default function Exceptions() {
  const principal = usePrincipal();
  const cache = useQueryClient();
  const toast = useToast();
  const list = useQuery({ queryKey: ["exceptions"], queryFn: ({ signal }) => apiGet<{ items: ExceptionItem[] }>("/api/v1/exceptions", signal) });
  const decide = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "approve" | "reject" | "revoke" }) => apiWrite(`/api/v1/exceptions/${id}/${action}`),
    onSuccess: async (_d, vars) => {
      toast("ok", `Exception ${{ approve: "approved", reject: "rejected", revoke: "revoked" }[vars.action]}`);
      await Promise.all(["exceptions", "findings", "overview"].map((k) => cache.invalidateQueries({ queryKey: [k] })));
    },
    onError: (error) => toast("err", error.message),
  });
  const me = principal.data;
  const approver = hasRole(me?.roles, "risk_approver");
  const revoker = hasRole(me?.roles, "risk_approver", "platform_admin");
  return (
    <>
      <PageHeading title="Exceptions" description="Time-boxed risk acceptances. An exception never changes a technical result — it expires and the finding becomes actionable again." />
      <section className="panel">
        <div className="panel-head"><h2>Exception register</h2><span className="sub">Self-approval is blocked server-side</span></div>
        {list.isPending && <Skeleton rows={4} />}
        {list.isError && <ErrorNotice error={list.error} />}
        {list.isSuccess && list.data.items.length === 0 && <Empty icon="exceptions" title="No exceptions">Request one from a finding’s detail panel.</Empty>}
        {list.isSuccess && list.data.items.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead><tr><th scope="col">Control</th><th scope="col">Asset</th><th scope="col">State</th><th scope="col">Requested by</th><th scope="col">Expires</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {list.data.items.map((item) => (
                  <tr key={item.id}>
                    <th scope="row">{shortKey(item.control_key)}<span className="cell-sub">{item.reason}</span></th>
                    <td>{item.asset_name}</td>
                    <td><StateChip state={item.effective_state} /></td>
                    <td>{item.requester_email.split("@")[0]}{item.approver_email && <span className="cell-sub">approved by {item.approver_email.split("@")[0]}</span>}</td>
                    <td>{when(item.expires_at)}</td>
                    <td className="num">
                      <div style={{ display: "inline-flex", gap: 6 }}>
                        {item.state === "REQUESTED" && approver && item.requested_by !== me?.user_id && <>
                          <button className="btn sm primary" disabled={decide.isPending} onClick={() => decide.mutate({ id: item.id, action: "approve" })}>Approve</button>
                          <button className="btn sm danger" disabled={decide.isPending} onClick={() => decide.mutate({ id: item.id, action: "reject" })}>Reject</button>
                        </>}
                        {item.state === "REQUESTED" && item.requested_by === me?.user_id && <span className="quiet">Awaiting another approver</span>}
                        {item.effective_state === "APPROVED" && revoker && <button className="btn sm danger" disabled={decide.isPending} onClick={() => decide.mutate({ id: item.id, action: "revoke" })}>Revoke</button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
