export interface BastionOverviewData {
  compliance_pct: number;
  completeness_pct: number;
  totals: {
    passed: number;
    failed: number;
    unknown: number;
    error: number;
    manual_required: number;
    not_applicable: number;
    total: number;
  };
  freshness: {
    fresh: number;
    stale: number;
    never: number;
    unreachable: number;
  };
  findings_by_state: {
    OPEN: number;
    RESOLVED: number;
    RISK_ACCEPTED: number;
  };
  open_by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  asset_count: number;
  latest_run: {
    id: string;
    created_at: string;
    status: string;
  };
  trend: Array<{ date: string; compliance_pct: number; completeness_pct: number }>;
}

export const MOCK_OVERVIEW: BastionOverviewData = {
  compliance_pct: 75.0,
  completeness_pct: 84.2,
  totals: {
    passed: 90,
    failed: 18,
    unknown: 8,
    error: 2,
    manual_required: 2,
    not_applicable: 14,
    total: 134,
  },
  freshness: {
    fresh: 14,
    stale: 2,
    never: 1,
    unreachable: 0,
  },
  findings_by_state: {
    OPEN: 18,
    RESOLVED: 42,
    RISK_ACCEPTED: 3,
  },
  open_by_severity: {
    critical: 4,
    high: 8,
    medium: 5,
    low: 1,
  },
  asset_count: 17,
  latest_run: {
    id: "run-98a12c",
    created_at: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
    status: "COMPLETED",
  },
  trend: [
    { date: "Oct 24", compliance_pct: 68.0, completeness_pct: 79.0 },
    { date: "Oct 25", compliance_pct: 70.5, completeness_pct: 80.5 },
    { date: "Oct 26", compliance_pct: 71.0, completeness_pct: 82.0 },
    { date: "Oct 27", compliance_pct: 73.5, completeness_pct: 83.0 },
    { date: "Oct 28", compliance_pct: 74.0, completeness_pct: 83.5 },
    { date: "Oct 29", compliance_pct: 75.0, completeness_pct: 84.2 },
  ],
};

export interface BastionAsset {
  id: string;
  name: string;
  platform: "linux" | "windows" | "cisco" | "fortigate";
  role: string;
  ip: string;
  site: string;
  owner: string;
  last_scan: string;
  reachability: "reachable" | "unreachable";
  capabilities: string[];
  trust_status: "verified" | "unverified";
  credential_state: "active" | "expiring_soon";
  compliance: number;
}

export const MOCK_ASSETS: BastionAsset[] = [
  {
    id: "ast-01",
    name: "web-prod-01",
    platform: "linux",
    role: "Production Web Server (Ubuntu 22.04 LTS)",
    ip: "10.20.1.11:22",
    site: "us-east-dc1",
    owner: "sec-team@northwind.example",
    last_scan: "25 minutes ago",
    reachability: "reachable",
    capabilities: ["SSH-2.0", "systemd", "auditd", "UFW"],
    trust_status: "verified",
    credential_state: "active",
    compliance: 88,
  },
  {
    id: "ast-02",
    name: "win-dc-01",
    platform: "windows",
    role: "Primary Domain Controller (Win Server 2019)",
    ip: "10.20.1.101:5986",
    site: "us-east-dc1",
    owner: "sysadmin@northwind.example",
    last_scan: "40 minutes ago",
    reachability: "reachable",
    capabilities: ["WinRM HTTPS", "SecEdit", "AuditPol", "Defender"],
    trust_status: "verified",
    credential_state: "active",
    compliance: 79,
  },
  {
    id: "ast-03",
    name: "edge-fw-01",
    platform: "fortigate",
    role: "Perimeter Security Gateway (FortiOS 7.4)",
    ip: "10.20.0.1:443",
    site: "us-east-dc1",
    owner: "netops@northwind.example",
    last_scan: "1 hour ago",
    reachability: "reachable",
    capabilities: ["HTTPS REST", "Syslog", "Policy Engine"],
    trust_status: "verified",
    credential_state: "active",
    compliance: 82,
  },
  {
    id: "ast-04",
    name: "core-sw-01",
    platform: "cisco",
    role: "Core Distribution Switch (Catalyst 9300)",
    ip: "10.20.0.2:22",
    site: "us-east-dc1",
    owner: "netops@northwind.example",
    last_scan: "2 hours ago",
    reachability: "reachable",
    capabilities: ["SSH-2.0", "Port-Security", "BPDU-Guard", "VLAN"],
    trust_status: "verified",
    credential_state: "active",
    compliance: 68,
  },
  {
    id: "ast-05",
    name: "db-cluster-01",
    platform: "linux",
    role: "Core PostgreSQL Cluster (RHEL 9)",
    ip: "10.20.2.21:22",
    site: "us-east-dc1",
    owner: "dba@northwind.example",
    last_scan: "3 hours ago",
    reachability: "reachable",
    capabilities: ["SSH-2.0", "SELinux", "sysctl", "systemd"],
    trust_status: "verified",
    credential_state: "active",
    compliance: 92,
  },
];

export interface BastionFinding {
  id: string;
  control_id: string;
  title: string;
  asset_name: string;
  platform: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "FAIL" | "PASS" | "UNKNOWN" | "ERROR" | "MANUAL_REQUIRED";
  expected_source: string;
  expected_custom: string;
  actual_value: string;
  evidence_excerpt: string;
  evidence_pointer: string;
  remediation_cmd: string;
  remediation_authority: string;
  owner: string;
  due_date: string;
}

export const MOCK_FINDINGS: BastionFinding[] = [
  {
    id: "fnd-01",
    control_id: "CIS-1.1.2",
    title: "Ensure VTY line exec-timeout is set to 300 seconds or less",
    asset_name: "core-sw-01",
    platform: "cisco",
    severity: "critical",
    status: "FAIL",
    expected_source: "exec-timeout <= 300 seconds",
    expected_custom: "exec-timeout <= 300 seconds",
    actual_value: "0 (infinite timeout / disabled)",
    evidence_excerpt: "line vty 0 4\n transport input ssh\n exec-timeout 0 0\n!",
    evidence_pointer: "running-config: line 42-45 (sha256: 449f...8a12)",
    remediation_cmd: "configure terminal\nline vty 0 4\n exec-timeout 5 0\nexit",
    remediation_authority: "Cisco IOS XE VTY Configuration",
    owner: "ava.chen@northwind.example",
    due_date: "In 4 days (Nov 3, 2026)",
  },
  {
    id: "fnd-02",
    control_id: "CIS-2.3.11.7",
    title: "Ensure SMBv1 protocol driver is disabled",
    asset_name: "win-dc-01",
    platform: "windows",
    severity: "high",
    status: "PASS",
    expected_source: "SMB1 == 0",
    expected_custom: "SMB1 == 0",
    actual_value: "0 (Disabled)",
    evidence_excerpt: "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters -> SMB1: 0",
    evidence_pointer: "registry: LanmanServer\\Parameters (sha256: 8a12...99ff)",
    remediation_cmd: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'SMB1' -Value 0",
    remediation_authority: "Domain Group Policy (GPO)",
    owner: "rowan.diaz@northwind.example",
    due_date: "Compliant",
  },
  {
    id: "fnd-03",
    control_id: "CIS-3.1.2",
    title: "Ensure zero permit-any-any firewall rules without security profiles",
    asset_name: "edge-fw-01",
    platform: "fortigate",
    severity: "critical",
    status: "FAIL",
    expected_source: "any_any_allow_count == 0",
    expected_custom: "any_any_allow_count == 0",
    actual_value: "1 rule permitting all sources and destinations",
    evidence_excerpt: "edit 14\n set srcaddr all\n set dstaddr all\n set action accept\n set schedule always\n set service all\nnext",
    evidence_pointer: "firewall policy: rule 14 (sha256: 1098...77ba)",
    remediation_cmd: "config firewall policy\n delete 14\nend",
    remediation_authority: "FortiGate Administrative Web UI / CLI",
    owner: "ava.chen@northwind.example",
    due_date: "In 2 days (Nov 1, 2026)",
  },
  {
    id: "fnd-04",
    control_id: "CIS-5.4.4",
    title: "Ensure default umask is 027 or more restrictive in login.defs",
    asset_name: "web-prod-01",
    platform: "linux",
    severity: "medium",
    status: "FAIL",
    expected_source: "umask in ['027', '077']",
    expected_custom: "umask in ['027', '077']",
    actual_value: "022 (Permits world read/execute)",
    evidence_excerpt: "/etc/login.defs: line 88 -> UMASK 022",
    evidence_pointer: "file: /etc/login.defs (sha256: ee91...3301)",
    remediation_cmd: "sed -i 's/^UMASK.*/UMASK 027/' /etc/login.defs",
    remediation_authority: "Local Security Configuration / Ansible",
    owner: "rowan.diaz@northwind.example",
    due_date: "In 7 days (Nov 6, 2026)",
  },
];

