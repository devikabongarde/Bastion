import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { apiGet, apiWrite, type Asset, type Page, type Site } from '../lib/api';
import { hasRole, useActivePolicy, usePrincipal, useOverview } from '../lib/hooks';
import { ago, when } from '../lib/format';
import { useToast } from '../components/ui';
import { Card } from '../components/shadcn/card';
import { Button } from '../components/shadcn/button';
import { Input } from '../components/shadcn/input';
import { Table, TableHeader, TableBody, TableHead, TableRow, TableCell } from '../components/shadcn/table';
import { Sheet, SheetHeader, SheetTitle, SheetDescription, SheetContent, SheetFooter } from '../components/shadcn/sheet';
import { AlertTriangle, CheckCircle2, Fingerprint, KeyRound, Monitor, Network, Play, Plus, Router, Search, Server, Shield, Upload } from 'lucide-react';

const MODE_LABEL: Record<Asset['collection_mode'], string> = {
  live_ssh: 'Live · SSH',
  live_local: 'Live · this machine',
  fixture: 'Fixture',
  import: 'Offline import',
};

function platformLabel(asset: Asset): string {
  const family = String(asset.identity?.family ?? asset.category);
  const version = asset.identity?.version ? ` ${String(asset.identity.version)}` : '';
  const names: Record<string, string> = {
    ubuntu: 'Ubuntu', windows: 'Windows', windows_server: 'Windows Server', cisco_ios_xe: 'Cisco IOS XE', fortigate: 'FortiGate',
  };
  return `${names[family] ?? family}${version}`;
}

function PlatformIcon({ asset }: { asset: Asset }) {
  const Icon = asset.category === 'windows' ? Monitor : asset.category === 'firewall' ? Shield : asset.category === 'router' ? Router : asset.category === 'switch' ? Network : Server;
  return <Icon className="w-4 h-4" />;
}

function isReady(asset: Asset): boolean {
  return asset.collection_mode === 'live_local' || (asset.collection_mode === 'live_ssh' && Boolean(asset.host_key_fingerprint) && asset.credential_bound);
}

/** Live scan for one or more assets, polling until the run finishes. */
function useLiveScan() {
  const cache = useQueryClient();
  const toast = useToast();
  const policy = useActivePolicy();
  const [scanId, setScanId] = useState<string | null>(null);
  const status = useQuery({
    queryKey: ['scan', scanId],
    queryFn: ({ signal }) => apiGet<{ status: string }>(`/api/v1/scans/${scanId}`, signal),
    enabled: Boolean(scanId),
    refetchInterval: 1000,
  });
  const final = status.data && ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELED', 'CANCELLED'].includes(status.data.status) ? status.data.status : null;
  useEffect(() => {
    if (!scanId || !final) return;
    setScanId(null);
    toast(final === 'FAILED' ? 'err' : 'ok', `Live scan ${final.toLowerCase()} — results updated`);
    void Promise.all(['assets', 'overview', 'findings', 'assessments'].map((key) => cache.invalidateQueries({ queryKey: [key] })));
  }, [scanId, final, toast, cache]);
  const start = useMutation({
    mutationFn: (assetIds: string[]) => apiWrite<{ scan_id: string }>('/api/v1/scans', {
      asset_ids: assetIds, policy_revision_id: policy.data?.id, reason: 'Live scan from Assets',
    }),
    onSuccess: (data) => setScanId(data.scan_id),
    onError: (error) => toast('err', error.message),
  });
  return { start, running: Boolean(scanId) || start.isPending, ready: Boolean(policy.data) };
}

export default function Assets() {
  const assetsQuery = useQuery({
    queryKey: ['assets', 'list'],
    queryFn: ({ signal }) => apiGet<Page<Asset>>('/api/v1/assets?limit=200', signal),
  });
  const overview = useOverview();
  const principal = usePrincipal();
  const cache = useQueryClient();
  const scan = useLiveScan();

  const [adding, setAdding] = useState(false);
  const [creatingSite, setCreatingSite] = useState(false);
  const [importingCsv, setImportingCsv] = useState(false);
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [connectId, setConnectId] = useState<string | null>(null);
  const [csvText, setCsvText] = useState('');
  const [defaultSite, setDefaultSite] = useState('');
  const [previewData, setPreviewData] = useState<any>(null);

  const sites = useQuery({
    queryKey: ['sites'],
    queryFn: ({ signal }) => apiGet<Page<Site>>('/api/v1/sites', signal),
    enabled: adding || importingCsv,
  });
  const createSite = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiWrite<Site>('/api/v1/sites', body),
    onSuccess: async () => { setCreatingSite(false); await cache.invalidateQueries({ queryKey: ['sites'] }); },
  });
  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => apiWrite('/api/v1/assets', body),
    onSuccess: async () => { setAdding(false); await cache.invalidateQueries({ queryKey: ['assets'] }); },
  });
  const archive = useMutation({
    mutationFn: (id: string) => apiWrite(`/api/v1/assets/${id}/archive`),
    onSuccess: async () => {
      await cache.invalidateQueries({ queryKey: ['assets'] });
      await cache.invalidateQueries({ queryKey: ['overview'] });
    },
  });
  const previewMutation = useMutation({
    mutationFn: (body: { csv_text: string; default_site_id?: string }) => apiWrite<any>('/api/v1/assets/import-preview', body),
    onSuccess: (data) => setPreviewData(data),
  });
  const commitMutation = useMutation({
    mutationFn: (body: { rows: Array<any> }) => apiWrite<{ created_count: number }>('/api/v1/assets/import-commit', body),
    onSuccess: async () => {
      setImportingCsv(false);
      setPreviewData(null);
      setCsvText('');
      await cache.invalidateQueries({ queryKey: ['assets'] });
      await cache.invalidateQueries({ queryKey: ['overview'] });
    },
  });

  const canEdit = hasRole(principal.data?.roles, 'inventory_editor', 'platform_admin');
  const canCreateSite = hasRole(principal.data?.roles, 'platform_admin');
  const canConnect = hasRole(principal.data?.roles, 'platform_admin', 'credential_admin');
  const canScan = hasRole(principal.data?.roles, 'scan_operator', 'platform_admin');
  const posture = useMemo(() => new Map(overview.data?.posture.map((row) => [row.asset_id, row])), [overview.data]);
  const assets = assetsQuery.data?.items ?? [];
  const filtered = assets.filter((a) => {
    if (!query) return true;
    const q = query.toLowerCase();
    return a.name.toLowerCase().includes(q) || a.address.includes(q) || platformLabel(a).toLowerCase().includes(q);
  });
  const selected = assets.find((a) => a.id === selectedId) ?? null;
  const readyLive = assets.filter(isReady);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="page-heading">
        <div>
          <p className="eyebrow">Workspace</p>
          <h1>Assets</h1>
          <p className="page-description">Every device Bastion audits, how its evidence is collected, and whether live collection is ready.</p>
        </div>
        <div className="top-actions">
          {canScan && readyLive.length > 0 && (
            <Button variant="outline" size="sm" disabled={scan.running || !scan.ready} onClick={() => scan.start.mutate(readyLive.map((a) => a.id))}>
              <Play className="w-4 h-4 mr-1.5" /> {scan.running ? 'Scanning…' : `Scan all live (${readyLive.length})`}
            </Button>
          )}
          {canCreateSite && (
            <Button variant="outline" size="sm" onClick={() => { createSite.reset(); setCreatingSite(true); }}>
              <Network className="w-4 h-4 mr-1.5" /> New site
            </Button>
          )}
          {canEdit && (
            <>
              <Button variant="outline" size="sm" onClick={() => { setImportingCsv(true); setPreviewData(null); }}>
                <Upload className="w-4 h-4 mr-1.5" /> Import CSV
              </Button>
              <Button variant="primary" size="sm" onClick={() => setAdding(true)}>
                <Plus className="w-4 h-4 mr-1.5" /> Add asset
              </Button>
            </>
          )}
        </div>
      </div>

      <Card className="p-4">
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-[var(--body-muted)]" />
          <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search by name, address or platform…" className="!pl-10 h-10 w-full" />
        </div>
      </Card>

      <Card className="overflow-x-auto p-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Asset</TableHead>
              <TableHead className="w-[150px]">Platform</TableHead>
              <TableHead className="w-[150px]">Collection</TableHead>
              <TableHead className="w-[170px]">Host key</TableHead>
              <TableHead className="w-[150px]">Compliance</TableHead>
              <TableHead className="w-[110px]">Last assessed</TableHead>
              <TableHead className="w-[130px] text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {assetsQuery.isPending ? (
              <TableRow><TableCell colSpan={7} className="h-24 text-center text-[var(--body-muted)]">Loading assets…</TableCell></TableRow>
            ) : assetsQuery.isError ? (
              <TableRow><TableCell colSpan={7} className="h-32 text-center form-error">Assets could not be loaded: {assetsQuery.error.message}</TableCell></TableRow>
            ) : filtered.length === 0 ? (
              <TableRow><TableCell colSpan={7} className="h-32 text-center text-[var(--body-muted)]">No assets match.</TableCell></TableRow>
            ) : (
              filtered.map((asset) => {
                const row = posture.get(asset.id);
                const pct = row?.compliance_pct;
                return (
                  <TableRow key={asset.id} onClick={() => setSelectedId(asset.id)} className="cursor-pointer">
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <span className="db-asset-icon"><PlatformIcon asset={asset} /></span>
                        <div>
                          <div className="font-semibold text-sm text-[var(--heading)] font-mono">{asset.name}</div>
                          <div className="text-xs text-[var(--body-muted)]">{asset.declared_role.replaceAll('_', ' ')} · {asset.address}:{asset.port}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell className="text-sm text-[var(--body)]">{platformLabel(asset)}</TableCell>
                    <TableCell><span className={`chip ${asset.collection_mode.startsWith('live') ? 'live' : 'import'}`}>{MODE_LABEL[asset.collection_mode]}</span></TableCell>
                    <TableCell className="text-xs">
                      {asset.collection_mode !== 'live_ssh' ? (
                        <span className="text-[var(--body-muted)]">Not applicable</span>
                      ) : asset.host_key_fingerprint ? (
                        <span className="inline-flex items-center gap-1 text-[var(--accent-text)] font-medium" title={asset.host_key_fingerprint}>
                          <Fingerprint className="w-3.5 h-3.5" /> Pinned
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-[var(--status-fail)] font-medium"><AlertTriangle className="w-3.5 h-3.5" /> Not pinned</span>
                      )}
                    </TableCell>
                    <TableCell>
                      {pct === null || pct === undefined ? (
                        <span className="text-xs text-[var(--body-muted)]">Not assessed</span>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="db-bar" style={{ width: 64 }}><i className={pct >= 90 ? 'good' : pct >= 60 ? 'warn' : 'bad'} style={{ width: `${pct}%` }} /></span>
                          <span className="text-xs font-semibold text-[var(--heading)]">{Math.round(pct)}%</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-[var(--body-muted)]">{row?.observed_at ? ago(row.observed_at) : '—'}</TableCell>
                    <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                      {isReady(asset) && canScan ? (
                        <Button variant="ghost" size="sm" className="text-xs" disabled={scan.running} onClick={() => scan.start.mutate([asset.id])}>
                          <Play className="w-3.5 h-3.5 mr-1" /> Scan
                        </Button>
                      ) : asset.collection_mode === 'live_ssh' && canConnect ? (
                        <Button variant="ghost" size="sm" className="text-xs" onClick={() => setConnectId(asset.id)}>
                          <KeyRound className="w-3.5 h-3.5 mr-1" /> Connect
                        </Button>
                      ) : (
                        <Link to={`/findings?asset=${asset.id}`} className="text-xs font-medium text-[var(--accent-text)]">Findings →</Link>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </Card>

      {/* Asset detail */}
      <Sheet open={Boolean(selected)} onOpenChange={(open) => !open && setSelectedId(null)} side="right">
        {selected && (
          <>
            <SheetHeader>
              <div className="flex items-center gap-2 mb-2">
                <span className={`chip ${selected.collection_mode.startsWith('live') ? 'live' : 'import'}`}>{MODE_LABEL[selected.collection_mode]}</span>
                <span className="text-xs font-mono text-[var(--body-muted)]">{selected.address}:{selected.port}</span>
              </div>
              <SheetTitle>{selected.name}</SheetTitle>
              <SheetDescription>{platformLabel(selected)} · {selected.declared_role.replaceAll('_', ' ')} · {selected.criticality} criticality</SheetDescription>
            </SheetHeader>
            <SheetContent className="space-y-5">
              <dl className="remediation-meta">
                <dt>Adapter</dt><dd><code>{selected.adapter_id}</code></dd>
                <dt>Host key</dt>
                <dd>
                  {selected.collection_mode !== 'live_ssh' ? 'Not applicable for this collection mode'
                    : selected.host_key_fingerprint ? <><code>{selected.host_key_fingerprint}</code><div className="text-xs text-[var(--body-muted)] mt-1">Pinned {when(selected.host_key_verified_at)} — any other key is refused.</div></>
                    : 'Not pinned — connect to read and confirm the device fingerprint.'}
                </dd>
                <dt>Credential</dt>
                <dd>{selected.collection_mode !== 'live_ssh' ? 'Not required' : selected.credential_bound ? 'Read-only audit credential bound (encrypted at rest)' : 'Not bound'}</dd>
                <dt>Compliance</dt>
                <dd>{posture.get(selected.id)?.compliance_pct ?? 'Not assessed'}{posture.get(selected.id)?.compliance_pct != null ? '%' : ''}</dd>
              </dl>
              <div className="grid gap-2">
                <Link to={`/findings?asset=${selected.id}`}><Button variant="primary" className="w-full">View findings</Button></Link>
                {isReady(selected) && canScan && (
                  <Button variant="outline" className="w-full" disabled={scan.running} onClick={() => scan.start.mutate([selected.id])}>
                    <Play className="w-4 h-4 mr-1.5" /> {scan.running ? 'Scanning…' : 'Scan now'}
                  </Button>
                )}
                {selected.collection_mode === 'live_ssh' && canConnect && (
                  <Button variant="outline" className="w-full" onClick={() => setConnectId(selected.id)}>
                    <KeyRound className="w-4 h-4 mr-1.5" /> {selected.host_key_fingerprint ? 'Re-pin host key & credential' : 'Connect'}
                  </Button>
                )}
                {canEdit && (
                  <Button variant="ghost" className="w-full text-[var(--status-fail)]" onClick={() => {
                    if (confirm(`Archive ${selected.name}? It stops being audited.`)) { archive.mutate(selected.id); setSelectedId(null); }
                  }}>Archive asset</Button>
                )}
              </div>
            </SheetContent>
            <SheetFooter><Button variant="outline" size="sm" onClick={() => setSelectedId(null)}>Close</Button></SheetFooter>
          </>
        )}
      </Sheet>

      {/* Connect (host-key pinning + credential) */}
      <Sheet open={Boolean(connectId)} onOpenChange={(open) => !open && setConnectId(null)} side="right">
        {connectId && <ConnectFlow asset={assets.find((a) => a.id === connectId)!} onDone={() => setConnectId(null)} />}
      </Sheet>

      {/* Create site: the network allow-list that live collection is confined to */}
      <Sheet open={creatingSite} onOpenChange={(open) => !open && setCreatingSite(false)}>
        <SheetHeader>
          <SheetTitle>New site</SheetTitle>
          <SheetDescription>Bastion only connects to addresses and ports inside a site's scope.</SheetDescription>
        </SheetHeader>
        <SheetContent>
          <form className="space-y-4" onSubmit={(e: FormEvent<HTMLFormElement>) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            const list = (name: string) => String(f.get(name) ?? '').split(/[\s,]+/).filter(Boolean);
            createSite.mutate({
              name: f.get('name'),
              timezone: f.get('timezone'),
              scope: {
                allowed_cidrs: list('cidrs'),
                allowed_ports: list('ports').map(Number),
                allowed_dns_suffixes: list('suffixes'),
              },
            });
          }}>
            <label className="field">Name<Input name="name" required placeholder="Ubuntu Lab" /></label>
            <label className="field">Timezone<Input name="timezone" required defaultValue={Intl.DateTimeFormat().resolvedOptions().timeZone} /></label>
            <label className="field">Allowed networks (CIDR)<Input name="cidrs" required placeholder="192.168.1.0/24" /></label>
            <div className="grid grid-cols-2 gap-3">
              <label className="field">Allowed ports<Input name="ports" required defaultValue="22" /></label>
              <label className="field">DNS suffixes (optional)<Input name="suffixes" placeholder="lab.example.edu" /></label>
            </div>
            <p className="quiet">Separate multiple values with commas. Use the narrowest range that covers the lab machines.</p>
            {createSite.isError && <p className="form-error">{createSite.error.message}</p>}
            <Button type="submit" variant="primary" className="w-full" disabled={createSite.isPending}>{createSite.isPending ? 'Creating…' : 'Create site'}</Button>
          </form>
        </SheetContent>
      </Sheet>

      {/* Register asset */}
      <Sheet open={adding} onOpenChange={(open) => !open && setAdding(false)}>
        <SheetHeader>
          <SheetTitle>Add asset</SheetTitle>
          <SheetDescription>The address must fall inside the selected site's authorized scope.</SheetDescription>
        </SheetHeader>
        <SheetContent>
          <form className="space-y-4" onSubmit={(e: FormEvent<HTMLFormElement>) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            create.mutate({
              site_id: f.get('site'), category: f.get('category'), name: f.get('name'), address: f.get('address'),
              port: Number(f.get('port')), adapter_id: f.get('adapter'), declared_role: f.get('role'),
              criticality: f.get('criticality'), tags: {},
            });
          }}>
            <label className="field">Site
              <select name="site" required>{sites.data?.items.map((x) => (
                <option key={x.id} value={x.id}>{x.name} · {x.scope.allowed_cidrs.join(', ')} · port {x.scope.allowed_ports.join(', ')}</option>
              ))}</select>
            </label>
            <label className="field">Name<Input name="name" required placeholder="web-prod-01" /></label>
            <div className="grid grid-cols-2 gap-3">
              <label className="field">Address<Input name="address" required placeholder="10.20.1.50" /></label>
              <label className="field">Port<Input name="port" type="number" defaultValue={22} /></label>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <label className="field">Category
                <select name="category">
                  <option value="linux">Linux server</option>
                  <option value="windows">Windows</option>
                  <option value="firewall">Firewall</option>
                  <option value="router">Router</option>
                  <option value="switch">Switch</option>
                </select>
              </label>
              <label className="field">Collection
                <select name="adapter">
                  <option value="linux-ssh">Linux · live SSH</option>
                  <option value="cisco-iosxe">Cisco IOS XE · live SSH</option>
                  <option value="fortigate-ssh">FortiGate · live SSH</option>
                  <option value="windows-local">Windows · this machine</option>
                </select>
              </label>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <label className="field">Role<Input name="role" defaultValue="server" /></label>
              <label className="field">Criticality
                <select name="criticality" defaultValue="high">{['critical', 'high', 'normal', 'low'].map((c) => <option key={c}>{c}</option>)}</select>
              </label>
            </div>
            {create.isError && <p className="form-error">{create.error.message}</p>}
            <Button type="submit" variant="primary" className="w-full" disabled={create.isPending}>{create.isPending ? 'Adding…' : 'Add asset'}</Button>
          </form>
        </SheetContent>
      </Sheet>

      {/* CSV import */}
      <Sheet open={importingCsv} onOpenChange={(open) => !open && setImportingCsv(false)}>
        <SheetHeader>
          <SheetTitle>Import assets from CSV</SheetTitle>
          <SheetDescription>Rows are validated first; nothing is saved until you commit.</SheetDescription>
        </SheetHeader>
        <SheetContent className="space-y-4">
          <form onSubmit={(e) => { e.preventDefault(); if (csvText.trim()) previewMutation.mutate({ csv_text: csvText, default_site_id: defaultSite || undefined }); }} className="space-y-4">
            <label className="field">Default site
              <select value={defaultSite} onChange={(e) => setDefaultSite(e.target.value)}>
                <option value="">Select a default site…</option>
                {sites.data?.items.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
              </select>
            </label>
            <div className="flex justify-between items-center">
              <span className="text-xs font-semibold text-[var(--body-muted)] uppercase">CSV</span>
              <button type="button" className="text-xs text-[var(--accent-text)] hover:underline" onClick={() => setCsvText(
                'name,address,port,category,criticality,role\napp-03,10.20.1.13,22,linux,high,server\nedge-fw-02,10.20.0.4,22,firewall,critical,firewall\naccess-sw-02,10.20.0.12,22,switch,high,switch\n',
              )}>Insert sample</button>
            </div>
            <textarea rows={6} value={csvText} onChange={(e) => setCsvText(e.target.value)} required
              placeholder="name,address,port,category,criticality,role…"
              className="w-full p-3 rounded-2xl border border-[var(--line-strong)] bg-[var(--surface)] text-[var(--heading)] font-mono text-xs outline-none" />
            <Button type="submit" variant="outline" className="w-full" disabled={previewMutation.isPending}>{previewMutation.isPending ? 'Validating…' : 'Validate rows'}</Button>
          </form>
          {previewMutation.isError && <p className="form-error">{previewMutation.error.message}</p>}
          {previewData && (
            <div className="p-4 rounded-2xl bg-[var(--mint-tint)] border border-[var(--line)] space-y-3">
              <div className="flex items-center justify-between text-xs font-mono">
                <span>Validation</span>
                <span className="font-bold text-[var(--accent-text)]">{previewData.valid_rows} / {previewData.total_rows} valid</span>
              </div>
              {previewData.rows.filter((r: any) => !r.valid).map((r: any) => (
                <p key={r.row_index} className="form-error">Row {r.row_index} ({r.name || 'unnamed'}): {r.errors.join(' ')}</p>
              ))}
              <Button variant="primary" className="w-full" disabled={commitMutation.isPending || previewData.valid_rows === 0} onClick={() => commitMutation.mutate({
                rows: previewData.rows.filter((r: any) => r.valid).map((r: any) => ({
                  name: r.name, address: r.address, port: r.port, category: r.category, criticality: r.criticality,
                  declared_role: r.declared_role, adapter_id: r.adapter_id, site_id: r.site_id, tags: {},
                })),
              })}>
                {commitMutation.isPending ? 'Saving…' : `Commit ${previewData.valid_rows} assets`}
              </Button>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function ConnectFlow({ asset, onDone }: { asset: Asset; onDone: () => void }) {
  const cache = useQueryClient();
  const toast = useToast();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const hostKey = useMutation({
    mutationFn: () => apiWrite<{ key_type: string; fingerprint: string }>(`/api/v1/assets/${asset.id}/host-key`),
  });
  const connect = useMutation({
    mutationFn: () => apiWrite(`/api/v1/assets/${asset.id}/connect`, {
      username, password, fingerprint: hostKey.data?.fingerprint,
    }),
    onSuccess: async () => {
      toast('ok', `${asset.name} connected — host key pinned`);
      await cache.invalidateQueries({ queryKey: ['assets'] });
      onDone();
    },
  });
  useEffect(() => { hostKey.mutate(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <>
      <SheetHeader>
        <SheetTitle>Connect {asset.name}</SheetTitle>
        <SheetDescription>{asset.address}:{asset.port} · {asset.adapter_id}</SheetDescription>
      </SheetHeader>
      <SheetContent className="space-y-5">
        <section>
          <h4 className="drawer-title"><Fingerprint className="w-4 h-4" /> 1 · Confirm the device's host key</h4>
          {hostKey.isPending && <p className="text-sm text-[var(--body-muted)]">Reading the SSH host key…</p>}
          {hostKey.isError && (
            <div className="space-y-2">
              <p className="form-error">{hostKey.error.message}</p>
              <Button variant="outline" size="sm" onClick={() => hostKey.mutate()}>Try again</Button>
            </div>
          )}
          {hostKey.data && (
            <div className="compare-card expected">
              <span>{hostKey.data.key_type}</span>
              <code>{hostKey.data.fingerprint}</code>
              <small>Compare with the device console (e.g. <code>show ip ssh</code> or <code>ssh-keygen -lf</code>) before trusting it.</small>
            </div>
          )}
        </section>
        <section>
          <h4 className="drawer-title"><KeyRound className="w-4 h-4" /> 2 · Read-only audit credential</h4>
          <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); connect.mutate(); }}>
            <label className="field">Username<Input value={username} onChange={(e) => setUsername(e.target.value)} required autoComplete="off" /></label>
            <label className="field">Password<Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required autoComplete="new-password" /></label>
            {connect.isError && <p className="form-error">{connect.error.message}</p>}
            <Button type="submit" variant="primary" className="w-full" disabled={!hostKey.data || connect.isPending}>
              <CheckCircle2 className="w-4 h-4 mr-1.5" /> {connect.isPending ? 'Pinning…' : 'Trust this key & connect'}
            </Button>
            <p className="text-xs text-[var(--body-muted)]">The credential is encrypted at rest and only used for read-only commands. If the device ever presents a different key, collection is refused.</p>
          </form>
        </section>
      </SheetContent>
    </>
  );
}
