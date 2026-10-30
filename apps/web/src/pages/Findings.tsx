import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { apiGet, apiWrite, type FindingDetail, type FindingItem } from '../lib/api';
import { ago, when } from '../lib/format';
import { hasRole, usePrincipal } from '../lib/hooks';
import { Card } from '../components/shadcn/card';
import { Button } from '../components/shadcn/button';
import { Input } from '../components/shadcn/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../components/shadcn/table';
import { Sheet, SheetHeader, SheetTitle, SheetDescription, SheetContent, SheetFooter } from '../components/shadcn/sheet';
import { Check, Copy, FileCheck2, History, Search, ShieldAlert, Terminal } from 'lucide-react';

const OPERATORS: Record<string, string> = { eq: '=', ne: '≠', lt: '<', lte: '≤', gt: '>', gte: '≥', in: 'one of', contains: 'contains' };

function show(value: unknown): string {
  if (value === null || value === undefined) return 'not observed';
  if (typeof value === 'string') return value;
  return JSON.stringify(value);
}

/** `management.vty.telnet_permitted` -> `Telnet permitted (management.vty)` */
function factLabel(key: string): string {
  const parts = key.split('.');
  const leaf = parts.pop() ?? key;
  return leaf.replaceAll('_', ' ').replace(/^\w/, (c) => c.toUpperCase());
}

function SeverityChip({ severity }: { severity: string }) {
  return <span className={`chip ${severity.toLowerCase()}`}>{severity.toUpperCase()}</span>;
}

function useCopy() {
  const [copied, setCopied] = useState<string | null>(null);
  return {
    copied,
    copy: (text: string, key: string) => {
      void navigator.clipboard.writeText(text);
      setCopied(key);
      window.setTimeout(() => setCopied(null), 2000);
    },
  };
}

export default function Findings() {
  const [params, setParams] = useSearchParams();
  const stateFilter = params.get('state') ?? 'OPEN';
  const severityFilter = params.get('severity') ?? '';
  const assetFilter = params.get('asset') ?? '';
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const search = new URLSearchParams({ limit: '200' });
  if (stateFilter) search.set('state', stateFilter);
  if (severityFilter) search.set('severity', severityFilter);
  if (assetFilter) search.set('asset_id', assetFilter);
  if (query) search.set('q', query);

  const findings = useQuery({
    queryKey: ['findings', stateFilter, severityFilter, assetFilter, query],
    queryFn: ({ signal }) => apiGet<{ items: FindingItem[]; total: number }>(`/api/v1/findings?${search}`, signal),
    refetchInterval: 15_000,
  });
  const items = findings.data?.items ?? [];
  const assetName = assetFilter ? items[0]?.asset_name ?? 'selected asset' : '';

  function setParam(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Workspace</p>
          <h1>Findings</h1>
          <p className="page-description">
            Every failed control with the expected value, the observed device configuration and exact remediation commands.
          </p>
        </div>
        <span className="text-xs font-mono text-[var(--body-muted)]">{findings.data?.total ?? items.length} findings</span>
      </div>

      <Card className="p-4">
        <div className="flex flex-col lg:flex-row lg:items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--body-muted)]" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by control, title or asset…" className="!pl-10 h-10 w-full" />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center rounded-full p-1 border border-[var(--line)]">
              {['OPEN', 'RISK_ACCEPTED', 'RESOLVED'].map((state) => (
                <button key={state} type="button" onClick={() => setParam('state', state)}
                  className={`px-3 py-1 rounded-full text-xs font-medium ${stateFilter === state ? 'bg-[var(--mint-tint)] text-[var(--heading)]' : 'text-[var(--body-muted)] hover:text-[var(--heading)]'}`}>
                  {state === 'RISK_ACCEPTED' ? 'Accepted' : state.charAt(0) + state.slice(1).toLowerCase()}
                </button>
              ))}
            </div>
            <div className="flex items-center rounded-full p-1 border border-[var(--line)]">
              {['', 'critical', 'high', 'medium', 'low'].map((sev) => (
                <button key={sev || 'all'} type="button" onClick={() => setParam('severity', sev)}
                  className={`px-3 py-1 rounded-full text-xs font-medium ${severityFilter === sev ? 'bg-[var(--mint-tint)] text-[var(--heading)]' : 'text-[var(--body-muted)] hover:text-[var(--heading)]'}`}>
                  {sev ? sev.charAt(0).toUpperCase() + sev.slice(1) : 'All'}
                </button>
              ))}
            </div>
            {assetFilter && (
              <Button variant="outline" size="sm" onClick={() => setParam('asset', '')} className="text-xs">
                {assetName} ×
              </Button>
            )}
          </div>
        </div>
      </Card>

      <Card className="overflow-x-auto p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[100px]">Severity</TableHead>
              <TableHead>Control</TableHead>
              <TableHead className="w-[170px]">Asset</TableHead>
              <TableHead className="w-[130px]">First seen</TableHead>
              <TableHead className="w-[150px]">Owner / due</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.isPending ? (
              <TableRow><TableCell colSpan={5} className="h-24 text-center text-[var(--body-muted)]">Loading findings…</TableCell></TableRow>
            ) : items.length === 0 ? (
              <TableRow><TableCell colSpan={5} className="h-32 text-center text-[var(--body-muted)]">No findings match these filters.</TableCell></TableRow>
            ) : (
              items.map((f) => (
                <TableRow key={f.id} onClick={() => setSelectedId(f.id)} className="cursor-pointer">
                  <TableCell><SeverityChip severity={f.severity} /></TableCell>
                  <TableCell>
                    <div className="font-medium text-sm text-[var(--heading)]">{f.title}</div>
                    <div className="text-xs text-[var(--body-muted)] font-mono mt-0.5">{f.control_key}</div>
                  </TableCell>
                  <TableCell><span className="font-mono text-xs text-[var(--heading)]">{f.asset_name}</span></TableCell>
                  <TableCell className="text-xs text-[var(--body-muted)]">{ago(f.first_seen_at)}</TableCell>
                  <TableCell className="text-xs text-[var(--body-muted)]">
                    {f.owner_email ?? 'Unassigned'}
                    {f.due_at && <div>due {when(f.due_at)}</div>}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </Card>

      <Sheet open={Boolean(selectedId)} onOpenChange={(open) => !open && setSelectedId(null)} side="right" className="sm:max-w-3xl">
        {selectedId && <FindingDrawer id={selectedId} onClose={() => setSelectedId(null)} />}
      </Sheet>
    </div>
  );
}

function FindingDrawer({ id, onClose }: { id: string; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ['finding', id],
    queryFn: ({ signal }) => apiGet<FindingDetail>(`/api/v1/findings/${id}`, signal),
  });
  const { copied, copy } = useCopy();

  if (detail.isPending) {
    return <SheetContent><p className="text-sm text-[var(--body-muted)]">Loading finding…</p></SheetContent>;
  }
  if (detail.isError || !detail.data) {
    return <SheetContent><p className="form-error">{detail.error?.message ?? 'Could not load this finding.'}</p></SheetContent>;
  }
  const f = detail.data;
  const result = f.last_result;
  const expected = (result?.expected ?? {}) as { fact?: string; operator?: string; value?: unknown };
  const actualMap = (result?.actual ?? {}) as Record<string, unknown>;
  const factKey = expected.fact ?? '';
  const observed = factKey in actualMap ? actualMap[factKey] : undefined;
  const evidence = (result?.evidence ?? []) as Array<{ reader_id?: string; artifact_sha256?: string; pointer?: { lines?: number[] } }>;
  const commands = f.remediation?.steps.join('\n') ?? '';

  return (
    <>
      <SheetHeader>
        <div className="flex items-center gap-2 mb-2">
          <span className={`chip ${result?.status === 'FAIL' ? 'fail' : 'neutral'}`}>{result?.status ?? f.state}</span>
          <SeverityChip severity={f.severity} />
          <span className="font-mono text-xs text-[var(--body-muted)]">{f.asset_name}</span>
        </div>
        <SheetTitle className="text-xl leading-snug">{f.title}</SheetTitle>
        <SheetDescription className="font-mono text-xs mt-1">{f.control_key}</SheetDescription>
      </SheetHeader>

      <SheetContent className="space-y-6">
        {/* Expected vs actual */}
        <section>
          <h4 className="drawer-title"><FileCheck2 className="w-4 h-4" /> Expected vs. actual configuration</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="compare-card expected">
              <span>Expected (policy)</span>
              <code>{factLabel(factKey)} {OPERATORS[expected.operator ?? ''] ?? expected.operator} {show(expected.value)}</code>
              <small className="font-mono">{factKey}</small>
            </div>
            <div className={`compare-card ${result?.status === 'FAIL' ? 'actual-fail' : 'actual'}`}>
              <span>Actual (device)</span>
              <code>{factLabel(factKey)} = {show(observed)}</code>
              <small>{result?.reason_code === 'ASSERTION_FAILED' ? 'Observed value violates the policy' : result?.reason_code?.replaceAll('_', ' ').toLowerCase()}</small>
            </div>
          </div>
        </section>

        {/* Evidence */}
        <section>
          <h4 className="drawer-title"><Terminal className="w-4 h-4" /> Evidence</h4>
          {evidence.length === 0 ? (
            <p className="text-xs text-[var(--body-muted)]">This result came from imported evidence without raw reader output.</p>
          ) : (
            <div className="evidence-list">
              {evidence.map((e, index) => (
                <div key={index}>
                  <code>{e.reader_id}</code>
                  <span>lines {e.pointer?.lines?.join('–')}</span>
                  <span className="font-mono" title={e.artifact_sha256}>sha256:{e.artifact_sha256?.slice(0, 16)}…</span>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Remediation */}
        <section>
          <div className="flex items-center justify-between mb-2">
            <h4 className="drawer-title !mb-0"><ShieldAlert className="w-4 h-4" /> Remediation</h4>
            {f.remediation && (
              <Button variant="ghost" size="sm" className="h-7 text-xs gap-1" onClick={() => copy(commands, 'fix')}>
                {copied === 'fix' ? <><Check className="w-3.5 h-3.5" /> Copied</> : <><Copy className="w-3.5 h-3.5" /> Copy commands</>}
              </Button>
            )}
          </div>
          {f.remediation ? (
            <>
              <p className="text-sm text-[var(--body)] mb-2">{f.remediation.summary}</p>
              <pre className="code-block">{commands}</pre>
              <dl className="remediation-meta">
                <dt>Verify</dt><dd><code>{f.remediation.verify}</code></dd>
                <dt>Authority</dt><dd>{f.remediation.authority}</dd>
                <dt>Impact</dt><dd>{f.remediation.impact}</dd>
              </dl>
              <p className="text-xs text-[var(--body-muted)] mt-2">Bastion never applies changes. Apply through your change process, then re-scan to close the finding.</p>
            </>
          ) : (
            <p className="text-xs text-[var(--body-muted)]">No remediation template is linked to this control.</p>
          )}
        </section>

        {/* History */}
        {f.events.length > 0 && (
          <section>
            <h4 className="drawer-title"><History className="w-4 h-4" /> History</h4>
            <ol className="history-list">
              {f.events.slice(0, 8).map((e, index) => (
                <li key={index}><b>{e.kind.replaceAll('_', ' ').toLowerCase()}</b><span>{when(e.at)}</span></li>
              ))}
            </ol>
          </section>
        )}

        <ExceptionForm finding={f} />
      </SheetContent>

      <SheetFooter>
        <Button variant="outline" size="sm" onClick={onClose}>Close</Button>
      </SheetFooter>
    </>
  );
}

function ExceptionForm({ finding }: { finding: FindingDetail }) {
  const principal = usePrincipal();
  const cache = useQueryClient();
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState('');
  const [controls, setControls] = useState('');
  const [days, setDays] = useState(30);
  const canRequest = hasRole(principal.data?.roles, 'analyst', 'platform_admin', 'scan_operator');
  const pending = finding.exceptions.find((e) => e.state === 'REQUESTED' || e.state === 'APPROVED');

  const submit = useMutation({
    mutationFn: () => apiWrite('/api/v1/exceptions', {
      asset_id: finding.asset_id,
      control_key: finding.control_key,
      reason,
      compensating_controls: controls,
      expires_at: new Date(Date.now() + days * 86_400_000).toISOString(),
    }),
    onSuccess: async () => {
      setOpen(false);
      setReason('');
      setControls('');
      await Promise.all(['finding', 'findings', 'exceptions'].map((key) => cache.invalidateQueries({ queryKey: [key] })));
    },
  });

  if (!canRequest) return null;
  return (
    <section className="p-4 rounded-2xl border border-[var(--line)] space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h5 className="font-semibold text-sm text-[var(--heading)]">Risk exception</h5>
          <p className="text-xs text-[var(--body-muted)]">
            {pending ? `An exception is ${pending.state.toLowerCase()} (expires ${when(pending.expires_at)}).` : 'Time-boxed; a different person must approve it.'}
          </p>
        </div>
        {!pending && (
          <Button variant="outline" size="sm" onClick={() => setOpen(!open)} className="text-xs">
            {open ? 'Cancel' : 'Request exception'}
          </Button>
        )}
      </div>
      {open && (
        <form className="space-y-3 pt-3 border-t border-[var(--line)]" onSubmit={(e) => { e.preventDefault(); submit.mutate(); }}>
          <Input placeholder="Business justification" value={reason} onChange={(e) => setReason(e.target.value)} required minLength={10} />
          <Input placeholder="Compensating controls in place" value={controls} onChange={(e) => setControls(e.target.value)} required minLength={10} />
          <label className="flex items-center gap-2 text-xs text-[var(--body)]">
            Expires in
            <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="px-2 py-1 rounded-lg border border-[var(--line-strong)] bg-[var(--surface)]">
              {[7, 30, 60, 90].map((d) => <option key={d} value={d}>{d} days</option>)}
            </select>
          </label>
          {submit.isError && <p className="form-error">{submit.error.message}</p>}
          <Button type="submit" variant="primary" size="sm" disabled={submit.isPending}>
            {submit.isPending ? 'Submitting…' : 'Submit for approval'}
          </Button>
        </form>
      )}
    </section>
  );
}
