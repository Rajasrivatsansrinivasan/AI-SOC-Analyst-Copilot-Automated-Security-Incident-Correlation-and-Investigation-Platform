// src/App.jsx
import { useEffect, useMemo, useRef, useState } from "react";
import {
  API_BASE,
  rebuildIncidents,
  getIncidents,
  getIncident,
  patchIncident,
  getAlerts,
  getPlaybook,
  simulateRemediate,
  exportIncident,
  connectAlertsWS,
} from "./api";

/** -----------------------------
 * Utilities
 * ------------------------------ */
function cx(...a) {
  return a.filter(Boolean).join(" ");
}

const LS_PREFIX = "soc-copilot:v1";
function lsKey(incidentId, name) {
  return `${LS_PREFIX}:incident:${incidentId}:${name}`;
}
function safeJsonParse(s, fallback) {
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
}
function lsGet(incidentId, name, fallback) {
  if (!incidentId) return fallback;
  const raw = localStorage.getItem(lsKey(incidentId, name));
  if (raw == null) return fallback;
  return safeJsonParse(raw, fallback);
}
function lsSet(incidentId, name, value) {
  if (!incidentId) return;
  try {
    localStorage.setItem(lsKey(incidentId, name), JSON.stringify(value));
  } catch {
    // ignore quota errors
  }
}
function lsRemove(incidentId, name) {
  if (!incidentId) return;
  try {
    localStorage.removeItem(lsKey(incidentId, name));
  } catch {
    // ignore
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** -----------------------------
 * UI atoms
 * ------------------------------ */
function SeverityBadge({ sev }) {
  const s = (sev || "").toLowerCase();
  const cls =
    s === "critical"
      ? "bg-red-500/15 text-red-200 ring-1 ring-red-500/30"
      : s === "high"
      ? "bg-orange-500/15 text-orange-200 ring-1 ring-orange-500/30"
      : s === "medium"
      ? "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/30"
      : "bg-slate-500/15 text-slate-200 ring-1 ring-slate-500/30";
  return (
    <span className={cx("px-2 py-1 rounded-full text-xs font-semibold", cls)}>
      {sev?.toUpperCase() || "UNKNOWN"}
    </span>
  );
}

function StatusPill({ status }) {
  const s = (status || "").toLowerCase();
  const cls =
    s === "open"
      ? "bg-blue-500/15 text-blue-200 ring-1 ring-blue-500/30"
      : s === "triaged"
      ? "bg-purple-500/15 text-purple-200 ring-1 ring-purple-500/30"
      : "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/30";
  return (
    <span className={cx("px-2 py-1 rounded-full text-xs font-semibold", cls)}>
      {status?.toUpperCase() || "OPEN"}
    </span>
  );
}

function RiskBar({ value }) {
  const v = Math.max(0, Math.min(100, Number(value || 0)));
  return (
    <div className="w-full">
      <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
        <div className="h-2 rounded-full bg-white/70" style={{ width: `${v}%` }} />
      </div>
      <div className="mt-1 text-xs text-slate-300">{v.toFixed(1)} / 100</div>
    </div>
  );
}

function Card({ title, value, sub }) {
  return (
    <div className="rounded-2xl bg-slate-900/60 ring-1 ring-slate-800 p-4">
      <div className="text-xs text-slate-400">{title}</div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
      {sub ? <div className="mt-1 text-xs text-slate-400">{sub}</div> : null}
    </div>
  );
}

function Section({ title, children, right }) {
  return (
    <div className="rounded-2xl bg-slate-900/50 ring-1 ring-slate-800">
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="text-sm font-semibold">{title}</div>
        <div>{right}</div>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function TabButton({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={cx(
        "px-3 py-1.5 rounded-lg text-sm ring-1 ring-slate-800 transition",
        active
          ? "bg-slate-800/70 text-white"
          : "bg-slate-900/30 text-slate-300 hover:bg-slate-800/40"
      )}
    >
      {children}
    </button>
  );
}

function Chip({ children }) {
  return (
    <span className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs bg-slate-950/50 ring-1 ring-slate-800 text-slate-200">
      {children}
    </span>
  );
}

/** -----------------------------
 * Panels
 * ------------------------------ */
function MitrePanel({ mitre }) {
  const rows = Array.isArray(mitre) ? mitre : [];
  if (!rows.length) {
    return <div className="text-sm text-slate-400">No MITRE mappings available for this incident.</div>;
  }

  return (
    <div className="overflow-auto rounded-xl ring-1 ring-slate-800">
      <table className="w-full text-sm">
        <thead className="bg-slate-900/60 text-slate-300">
          <tr>
            <th className="text-left px-3 py-2 font-semibold">Tactic</th>
            <th className="text-left px-3 py-2 font-semibold">Technique ID</th>
            <th className="text-left px-3 py-2 font-semibold">Technique</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((m, idx) => (
            <tr key={`${m.technique_id || m.id || "t"}-${idx}`} className="border-t border-slate-800">
              <td className="px-3 py-2">
                <Chip>{m.tactic || m.tactic_name || "-"}</Chip>
              </td>
              <td className="px-3 py-2 font-mono text-slate-200">{m.technique_id || m.id || "-"}</td>
              <td className="px-3 py-2 text-slate-200">{m.technique || m.technique_name || "-"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function computeIocsFromAlerts(alerts) {
  const normalized = Array.isArray(alerts) ? alerts : [];
  const ips = new Set();
  const users = new Set();
  const hosts = new Set();
  const alertTypes = new Set();

  for (const a of normalized) {
    const ip = (a?.ip || "").trim();
    const user = (a?.user || "").trim();
    const host = (a?.host || "").trim();
    const at = (a?.alert_type || "").trim();

    if (ip) ips.add(ip);
    if (user) users.add(user);
    if (host) hosts.add(host);
    if (at) alertTypes.add(at);
  }

  return {
    ips: Array.from(ips).sort(),
    users: Array.from(users).sort(),
    hosts: Array.from(hosts).sort(),
    alertTypes: Array.from(alertTypes).sort(),
  };
}

function IocPanel({ alerts }) {
  const iocs = useMemo(() => computeIocsFromAlerts(alerts), [alerts]);

  async function copyList(label, arr) {
    const text = arr.join("\n");
    const ok = await copyText(text);
    alert(ok ? `Copied ${label} ✅` : `Copy failed ❌ (try manually)`);
  }

  return (
    <div className="space-y-4">
      <div className="text-sm text-slate-300">
        Auto-extracted indicators from incident alerts (use these for investigation, blocking, and searches).
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">IPs</div>
            <button
              onClick={() => copyList("IPs", iocs.ips)}
              className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
              disabled={!iocs.ips.length}
            >
              Copy
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {iocs.ips.length ? iocs.ips.map((x) => <Chip key={x}>{x}</Chip>) : <div className="text-xs text-slate-400">None</div>}
          </div>
        </div>

        <div className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">Users</div>
            <button
              onClick={() => copyList("Users", iocs.users)}
              className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
              disabled={!iocs.users.length}
            >
              Copy
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {iocs.users.length ? iocs.users.map((x) => <Chip key={x}>{x}</Chip>) : <div className="text-xs text-slate-400">None</div>}
          </div>
        </div>

        <div className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">Hosts</div>
            <button
              onClick={() => copyList("Hosts", iocs.hosts)}
              className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
              disabled={!iocs.hosts.length}
            >
              Copy
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {iocs.hosts.length ? iocs.hosts.map((x) => <Chip key={x}>{x}</Chip>) : <div className="text-xs text-slate-400">None</div>}
          </div>
        </div>

        <div className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
          <div className="flex items-center justify-between">
            <div className="font-semibold">Alert Types</div>
            <button
              onClick={() => copyList("Alert Types", iocs.alertTypes)}
              className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
              disabled={!iocs.alertTypes.length}
            >
              Copy
            </button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {iocs.alertTypes.length ? (
              iocs.alertTypes.map((x) => <Chip key={x}>{x}</Chip>)
            ) : (
              <div className="text-xs text-slate-400">None</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function CodeBlock({ title, text, onCopy }) {
  return (
    <div className="rounded-xl bg-slate-950/40 ring-1 ring-slate-800">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800">
        <div className="text-sm font-semibold">{title}</div>
        <button
          onClick={onCopy}
          className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
        >
          Copy
        </button>
      </div>
      <pre className="p-3 text-xs overflow-auto whitespace-pre-wrap text-slate-200 font-mono">{text}</pre>
    </div>
  );
}

function QueriesPanel({ iocs }) {
  const queries = useMemo(() => {
    const ips = iocs?.ips || [];
    const users = iocs?.users || [];
    const hosts = iocs?.hosts || [];

    const kqlParts = [];
    if (ips.length) kqlParts.push(`IpAddress in (${ips.map((x) => `"${x}"`).join(", ")})`);
    if (users.length) kqlParts.push(`AccountName in (${users.map((x) => `"${x}"`).join(", ")})`);
    if (hosts.length) kqlParts.push(`Computer in (${hosts.map((x) => `"${x}"`).join(", ")})`);

    const kql = kqlParts.length
      ? `SecurityEvent
| where TimeGenerated > ago(7d)
| where ${kqlParts.join(" or ")}
| project TimeGenerated, Computer, Account, Activity, IpAddress, EventID, RenderedDescription
| order by TimeGenerated desc`
      : `// No IoCs yet – rebuild/seed to generate alerts`;

    const splunkParts = [];
    if (ips.length) splunkParts.push(`(src_ip IN (${ips.join(", ")}) OR dest_ip IN (${ips.join(", ")}))`);
    if (users.length) splunkParts.push(`user IN (${users.join(", ")})`);
    if (hosts.length) splunkParts.push(`host IN (${hosts.join(", ")})`);

    const splunk = splunkParts.length
      ? `index=* earliest=-7d
${splunkParts.join(" OR ")}
| table _time host user src_ip dest_ip sourcetype signature message
| sort - _time`
      : `# No IoCs yet – rebuild/seed to generate alerts`;

    const aws = ips.length
      ? `# CloudTrail Athena (example)
# Replace table/db names with your setup
SELECT eventTime, eventSource, eventName, sourceIPAddress, userIdentity.arn
FROM cloudtrail_logs
WHERE from_iso8601_timestamp(eventTime) > now() - INTERVAL '7' DAY
  AND sourceIPAddress IN (${ips.map((x) => `'${x}'`).join(", ")})
ORDER BY eventTime DESC;`
      : `# No IPs yet`;

    return { kql, splunk, aws };
  }, [iocs]);

  async function doCopy(label, text) {
    const ok = await copyText(text);
    alert(ok ? `Copied ${label} ✅` : `Copy failed ❌`);
  }

  return (
    <div className="space-y-3">
      <div className="text-sm text-slate-300">
        Ready-to-run queries built from current IoCs (edit time range/index/table as needed).
      </div>
      <div className="grid grid-cols-1 gap-3">
        <CodeBlock title="Microsoft Sentinel / KQL" text={queries.kql} onCopy={() => doCopy("KQL", queries.kql)} />
        <CodeBlock title="Splunk" text={queries.splunk} onCopy={() => doCopy("Splunk", queries.splunk)} />
        <CodeBlock title="AWS CloudTrail (Athena example)" text={queries.aws} onCopy={() => doCopy("AWS query", queries.aws)} />
      </div>
    </div>
  );
}

function buildInvestigatorPack({ incident, detail, alerts, mitre, iocs, queries, checklist, actionLogs }) {
  return {
    generated_at: new Date().toISOString(),
    incident: {
      id: incident?.id,
      title: incident?.title,
      severity: incident?.severity,
      status: incident?.status,
      confidence: incident?.confidence,
      risk_score: incident?.risk_score,
      analyst_verdict: incident?.analyst_verdict,
      analyst_notes: detail?.analyst_notes || incident?.analyst_notes || "",
      summary: detail?.summary || incident?.summary || "",
    },
    mitre: mitre || [],
    iocs: iocs || { ips: [], users: [], hosts: [], alertTypes: [] },
    queries: queries || {},
    timeline: (alerts || []).map((a) => ({
      ts: a.ts,
      source: a.source,
      alert_type: a.alert_type,
      message: a.message,
      user: a.user,
      host: a.host,
      ip: a.ip,
      severity: a.severity,
    })),
    checklist: checklist || {},
    action_log: actionLogs || [],
  };
}

function ChecklistRow({ checked, title, subtitle, badge, onToggle, disabled }) {
  return (
    <button
      onClick={disabled ? undefined : onToggle}
      className={cx(
        "w-full text-left rounded-xl ring-1 ring-slate-800 p-3 flex items-start justify-between gap-3 transition",
        checked ? "bg-emerald-500/10" : "bg-slate-950/30 hover:bg-slate-950/40",
        disabled ? "cursor-default" : "cursor-pointer"
      )}
    >
      <div className="flex items-start gap-3">
        <div
          className={cx(
            "mt-0.5 h-4 w-4 rounded border grid place-items-center",
            checked ? "bg-emerald-500/25 border-emerald-500/40" : "bg-transparent border-slate-700"
          )}
        >
          {checked ? <span className="text-emerald-200 text-xs">✓</span> : null}
        </div>
        <div>
          <div className="font-semibold">{title}</div>
          {subtitle ? <div className="mt-1 text-xs text-slate-400">{subtitle}</div> : null}
        </div>
      </div>
      <span
        className={cx(
          "shrink-0 text-xs px-2 py-1 rounded-full ring-1",
          badge === "auto"
            ? "bg-slate-900/40 text-slate-200 ring-slate-700"
            : "bg-slate-900/20 text-slate-300 ring-slate-800"
        )}
      >
        {badge}
      </span>
    </button>
  );
}

/** -----------------------------
 * Timeline polish
 * ------------------------------ */
function dotCls(sev) {
  const s = (sev || "").toLowerCase();
  if (s === "critical") return "bg-red-400 ring-red-400/40";
  if (s === "high") return "bg-orange-400 ring-orange-400/40";
  if (s === "medium") return "bg-yellow-300 ring-yellow-300/40";
  return "bg-slate-400 ring-slate-400/40";
}
function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return String(ts);
  return d.toLocaleString();
}

function TimelinePanel({ alerts, order = "oldest" }) {
  const rows = Array.isArray(alerts) ? alerts : [];

  const sorted = useMemo(() => {
    const copy = [...rows];
    copy.sort((a, b) => {
      const ta = new Date(a?.ts || 0).getTime();
      const tb = new Date(b?.ts || 0).getTime();
      const va = Number.isNaN(ta) ? 0 : ta;
      const vb = Number.isNaN(tb) ? 0 : tb;
      return order === "newest" ? vb - va : va - vb;
    });
    return copy;
  }, [rows, order]);

  if (!sorted.length) {
    return <div className="text-sm text-slate-400">No alert events available for this incident.</div>;
  }

  return (
    <div className="space-y-3">
      <div className="text-sm text-slate-300">
        Vertical timeline of alert events (sorted by time). Click an event to quickly copy its message.
      </div>

      <div className="relative rounded-2xl bg-slate-950/25 ring-1 ring-slate-800 p-4">
        <div className="absolute left-7 top-4 bottom-4 w-px bg-slate-800" />

        <div className="space-y-4">
          {sorted.map((a, idx) => {
            const key = a.id || `${a.ts}-${a.alert_type}-${idx}`;
            const sev = a.severity || "low";
            const dot = dotCls(sev);

            return (
              <button
                key={key}
                onClick={async () => {
                  const ok = await copyText(a?.message || "");
                  if (ok) alert("Copied message ✅");
                }}
                className="w-full text-left group"
              >
                <div className="grid grid-cols-[3.25rem_1fr] gap-3">
                  <div className="relative">
                    <div
                      className={cx("absolute left-5 top-1.5 h-4 w-4 rounded-full ring-4", dot, "ring-slate-950/60")}
                    />
                  </div>

                  <div className={cx("rounded-2xl ring-1 ring-slate-800 bg-slate-950/35 p-3 transition", "group-hover:bg-slate-950/45")}>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="text-xs text-slate-400">{fmtTime(a.ts)}</div>
                      <div className="flex items-center gap-2 text-xs text-slate-300">
                        <Chip>{a.source || "-"}</Chip>
                        <Chip>{a.alert_type || "-"}</Chip>
                        <span className={cx("px-2 py-1 rounded-full text-xs ring-1", dot, "bg-slate-950/20")}>
                          {(sev || "low").toUpperCase()}
                        </span>
                      </div>
                    </div>

                    <div className="mt-2 text-sm text-slate-200 whitespace-pre-wrap">{a.message}</div>

                    <div className="mt-2 text-xs text-slate-400">
                      user={a.user || "-"} • host={a.host || "-"} • ip={a.ip || "-"}
                    </div>

                    <div className="mt-2 text-[11px] text-slate-500">Tip: click to copy message</div>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/** -----------------------------
 * App
 * ------------------------------ */
export default function App() {
  const [apiBase] = useState(API_BASE);

  // Real-time streaming status
  const [wsStatus, setWsStatus] = useState("disconnected"); // disconnected | connecting | connected
  const refreshTimerRef = useRef(null);

  const [loading, setLoading] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedId, setSelectedId] = useState(null);

  const [q, setQ] = useState("");
  const [sevFilter, setSevFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const [tab, setTab] = useState("summary");

  const [detail, setDetail] = useState(null);
  const [playbook, setPlaybook] = useState([]);
  const [action, setAction] = useState("");

  // editable fields
  const [notes, setNotes] = useState("");
  const [verdict, setVerdict] = useState("unknown");
  const [status, setStatus] = useState("open");

  // Timeline sort toggle
  const [timelineOrder, setTimelineOrder] = useState("oldest"); // "oldest" | "newest"

  // Action log (persist per incident)
  const [actionLogs, setActionLogs] = useState([]);

  function addLog(actionName, meta = "") {
    setActionLogs((prev) => {
      const next = [{ ts: new Date().toISOString(), action: actionName, meta }, ...prev];
      return next.slice(0, 200);
    });
  }

  // Manual checklist items (persist per incident)
  const [manualChecks, setManualChecks] = useState({
    contain: false,
    eradicate: false,
    recover: false,
    document: false,
  });

  function resetChecklist() {
    setManualChecks({ contain: false, eradicate: false, recover: false, document: false });
  }

  /** -----------------------------
   * Persistence layer (localStorage per incident)
   * ------------------------------ */

  useEffect(() => {
    if (!selectedId) return;

    const persistedLogs = lsGet(selectedId, "actionLogs", []);
    if (Array.isArray(persistedLogs)) setActionLogs(persistedLogs);

    const persistedChecks = lsGet(selectedId, "manualChecks", null);
    if (persistedChecks && typeof persistedChecks === "object") {
      setManualChecks({
        contain: !!persistedChecks.contain,
        eradicate: !!persistedChecks.eradicate,
        recover: !!persistedChecks.recover,
        document: !!persistedChecks.document,
      });
    } else {
      setManualChecks({ contain: false, eradicate: false, recover: false, document: false });
    }

    const draft = lsGet(selectedId, "draft", null);
    if (draft && typeof draft === "object") {
      if (typeof draft.notes === "string") setNotes(draft.notes);
      if (typeof draft.verdict === "string") setVerdict(draft.verdict);
      if (typeof draft.status === "string") setStatus(draft.status);
    }
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId) return;
    lsSet(selectedId, "actionLogs", actionLogs);
  }, [selectedId, actionLogs]);

  useEffect(() => {
    if (!selectedId) return;
    lsSet(selectedId, "manualChecks", manualChecks);
  }, [selectedId, manualChecks]);

  useEffect(() => {
    if (!selectedId) return;
    lsSet(selectedId, "draft", { notes, verdict, status });
  }, [selectedId, notes, verdict, status]);

  /** -----------------------------
   * Data loading
   * ------------------------------ */
  async function loadAll() {
    setLoading(true);
    try {
      const [incs, als] = await Promise.all([getIncidents(), getAlerts()]);
      setIncidents(incs || []);
      setAlerts(als || []);
      if (!selectedId && incs?.length) setSelectedId(incs[0].id);
      addLog("Refresh", `Loaded ${incs?.length || 0} incidents`);
    } finally {
      setLoading(false);
    }
  }

  async function doRebuild() {
    setLoading(true);
    try {
      await rebuildIncidents();
      addLog("Rebuild Incidents", "Triggered /incidents/rebuild");
      await loadAll();
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(id) {
    if (!id) return;
    setLoading(true);
    try {
      const d = await getIncident(id);
      setDetail(d);

      const draft = lsGet(id, "draft", null);
      if (!draft) {
        setNotes(d?.analyst_notes || "");
        setVerdict(d?.analyst_verdict || "unknown");
        setStatus(d?.status || "open");
      }

      const pb = await getPlaybook(id);
      const steps = pb?.steps || [];
      setPlaybook(steps);
      setAction(steps?.[0]?.action || "");
      addLog("Open Incident", `Incident #${id}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    loadDetail(selectedId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  /** -----------------------------
   * ✅ REAL-TIME: WebSocket connect + live updates
   * ------------------------------ */
  useEffect(() => {
    setWsStatus("connecting");

    const client = connectAlertsWS({
      onOpen: () => setWsStatus("connected"),
      onClose: () => setWsStatus("disconnected"),
      onError: () => setWsStatus("disconnected"),
      onMessage: (payload) => {
        // Accept either {alert: {...}} or direct alert object
        const a = payload?.alert || payload;
        if (!a || typeof a !== "object") return;

        // Must look like an alert
        const hasAnyField =
          a.ts || a.message || a.alert_type || a.source || a.id || a.severity || a.ip || a.user || a.host;
        if (!hasAnyField) return;

        // 1) Update top-bar alerts count instantly
        setAlerts((prev) => {
          const arr = Array.isArray(prev) ? prev : [];
          if (a.id != null && arr.some((x) => x?.id === a.id)) return arr; // de-dupe
          return [a, ...arr].slice(0, 5000);
        });

        // 2) If it belongs to currently opened incident, inject into detail timeline instantly
        const incId = a.incident_id != null && a.incident_id !== "" ? Number(a.incident_id) : null;
        if (incId && selectedId && Number(selectedId) === Number(incId)) {
          setDetail((prev) => {
            if (!prev) return prev;
            const currentAlerts = Array.isArray(prev.alerts) ? prev.alerts : [];
            if (a.id != null && currentAlerts.some((x) => x?.id === a.id)) return prev;
            return { ...prev, alerts: [a, ...currentAlerts] };
          });
        }

        // 3) Soft refresh incidents/details (so risk scores/status can update) — debounced
        // Only do this if backend actually correlates alerts -> incidents.
        if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = setTimeout(() => {
          loadAll();
          if (selectedId) loadDetail(selectedId);
        }, 600);

        addLog("Realtime Alert", a.alert_type ? `${a.alert_type}` : `alert#${a.id || "-"}`);
      },
    });

    return () => {
      try {
        client?.close?.();
      } catch {
        // ignore
      }
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [apiBase, selectedId]);

  /** -----------------------------
   * Derived data
   * ------------------------------ */
  const kpis = useMemo(() => {
    const open = incidents.filter((i) => (i.status || "").toLowerCase() === "open").length;
    const critical = incidents.filter((i) => (i.severity || "").toLowerCase() === "critical").length;
    const avgRisk =
      incidents.length === 0 ? 0 : incidents.reduce((s, x) => s + Number(x.risk_score || 0), 0) / incidents.length;
    return { open, critical, avgRisk };
  }, [incidents]);

  const filtered = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return (incidents || [])
      .filter((i) => (sevFilter === "all" ? true : (i.severity || "").toLowerCase() === sevFilter))
      .filter((i) => (statusFilter === "all" ? true : (i.status || "").toLowerCase() === statusFilter))
      .filter((i) => {
        if (!qq) return true;
        const s = `${i.title} ${i.severity} ${i.status} ${i.analyst_verdict} ${i.summary}`.toLowerCase();
        return s.includes(qq);
      })
      .sort((a, b) => Number(b.risk_score || 0) - Number(a.risk_score || 0));
  }, [incidents, q, sevFilter, statusFilter]);

  const selected = useMemo(() => filtered.find((x) => x.id === selectedId) || detail, [filtered, selectedId, detail]);

  const detailAlerts = detail?.alerts || selected?.alerts || [];
  const mitreRows = detail?.mitre || selected?.mitre || [];
  const iocs = useMemo(() => computeIocsFromAlerts(detailAlerts), [detailAlerts]);

  const queriesObj = useMemo(() => {
    const ips = iocs?.ips || [];
    const users = iocs?.users || [];
    const hosts = iocs?.hosts || [];

    const kqlParts = [];
    if (ips.length) kqlParts.push(`IpAddress in (${ips.map((x) => `"${x}"`).join(", ")})`);
    if (users.length) kqlParts.push(`AccountName in (${users.map((x) => `"${x}"`).join(", ")})`);
    if (hosts.length) kqlParts.push(`Computer in (${hosts.map((x) => `"${x}"`).join(", ")})`);

    const kql = kqlParts.length
      ? `SecurityEvent
| where TimeGenerated > ago(7d)
| where ${kqlParts.join(" or ")}
| project TimeGenerated, Computer, Account, Activity, IpAddress, EventID, RenderedDescription
| order by TimeGenerated desc`
      : `// No IoCs yet – rebuild/seed to generate alerts`;

    const splunkParts = [];
    if (ips.length) splunkParts.push(`(src_ip IN (${ips.join(", ")}) OR dest_ip IN (${ips.join(", ")}))`);
    if (users.length) splunkParts.push(`user IN (${users.join(", ")})`);
    if (hosts.length) splunkParts.push(`host IN (${hosts.join(", ")})`);

    const splunk = splunkParts.length
      ? `index=* earliest=-7d
${splunkParts.join(" OR ")}
| table _time host user src_ip dest_ip sourcetype signature message
| sort - _time`
      : `# No IoCs yet – rebuild/seed to generate alerts`;

    return { kql, splunk };
  }, [iocs]);

  const autoChecks = useMemo(() => {
    const autoScope = Boolean(selected?.title);
    const autoValidate = selected?.confidence != null;
    const autoIocs = iocs.ips.length + iocs.users.length + iocs.hosts.length + iocs.alertTypes.length > 0;
    const autoMitre = Array.isArray(mitreRows) && mitreRows.length > 0;
    const autoTimeline = Array.isArray(detailAlerts) && detailAlerts.length > 0;

    return { scope: autoScope, validate: autoValidate, iocs: autoIocs, mitre: autoMitre, timeline: autoTimeline };
  }, [selected, iocs, mitreRows, detailAlerts]);

  const checklistDoneCount = useMemo(() => {
    const autoCount = Object.values(autoChecks).filter(Boolean).length;
    const manualCount = Object.values(manualChecks).filter(Boolean).length;
    return autoCount + manualCount;
  }, [autoChecks, manualChecks]);

  /** -----------------------------
   * Actions
   * ------------------------------ */
  async function saveCase() {
    if (!selectedId) return;
    setLoading(true);
    try {
      await patchIncident(selectedId, { analyst_notes: notes, analyst_verdict: verdict, status });
      addLog("Save Case", `verdict=${verdict}, status=${status}`);
      lsRemove(selectedId, "draft");
      await loadAll();
      await loadDetail(selectedId);
    } finally {
      setLoading(false);
    }
  }

  async function runAction() {
    if (!selectedId || !action) return;
    setLoading(true);
    try {
      await simulateRemediate(selectedId, action);
      addLog("Simulate Remediation", action);
      await loadAll();
      await loadDetail(selectedId);
      setTab("notes");
    } finally {
      setLoading(false);
    }
  }

  async function downloadExport() {
    if (!selectedId) return;
    const data = await exportIncident(selectedId);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident_${selectedId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    addLog("Export Incident JSON", `Incident #${selectedId}`);
  }

  async function copyChecklist() {
    const lines = [
      "Triage Checklist",
      `Incident #${selected?.id || "-"}`,
      "",
      `✅ Confirm scope and affected assets: ${autoChecks.scope ? "done" : "pending"}`,
      `✅ Validate signal (TP/FP): ${autoChecks.validate ? "done" : "pending"}`,
      `✅ Extract IoCs: ${autoChecks.iocs ? "done" : "pending"}`,
      `✅ Check MITRE mapping: ${autoChecks.mitre ? "done" : "pending"}`,
      `✅ Review timeline: ${autoChecks.timeline ? "done" : "pending"}`,
      `⬜ Contain threat: ${manualChecks.contain ? "done" : "pending"}`,
      `⬜ Eradicate: ${manualChecks.eradicate ? "done" : "pending"}`,
      `⬜ Recovery + monitoring: ${manualChecks.recover ? "done" : "pending"}`,
      `⬜ Document outcome + close/triage: ${manualChecks.document ? "done" : "pending"}`,
    ];
    const ok = await copyText(lines.join("\n"));
    alert(ok ? "Checklist copied ✅" : "Copy failed ❌");
    addLog("Copy Checklist", "");
  }

  async function downloadInvestigatorPack() {
    if (!selectedId) return;

    const pack = buildInvestigatorPack({
      incident: selected,
      detail,
      alerts: detailAlerts,
      mitre: mitreRows,
      iocs,
      queries: queriesObj,
      checklist: { auto: autoChecks, manual: manualChecks },
      actionLogs: actionLogs,
    });

    const blob = new Blob([JSON.stringify(pack, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `investigator_pack_incident_${selectedId}.json`;
    a.click();
    URL.revokeObjectURL(url);

    addLog("Export Investigator Pack", `Incident #${selectedId}`);
  }

  const wsBadge =
    wsStatus === "connected"
      ? "bg-emerald-500/15 text-emerald-200 ring-1 ring-emerald-500/30"
      : wsStatus === "connecting"
      ? "bg-yellow-500/15 text-yellow-200 ring-1 ring-yellow-500/30"
      : "bg-slate-500/15 text-slate-200 ring-1 ring-slate-500/30";

  /** -----------------------------
   * Render
   * ------------------------------ */
  return (
    <div className="min-h-full">
      <div className="sticky top-0 z-10 backdrop-blur bg-slate-950/60 border-b border-slate-900">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="h-9 w-9 rounded-xl bg-white/5 ring-1 ring-white/10 grid place-items-center">🔐</div>
            <div>
              <div className="text-sm font-semibold">AI SOC Analyst Copilot</div>
              <div className="text-xs text-slate-400 flex items-center gap-2 flex-wrap">
                <span>React Dashboard • Backend: {apiBase} • Alerts: {alerts?.length || 0}</span>
                <span className={cx("px-2 py-0.5 rounded-full text-[11px] font-semibold", wsBadge)}>
                  RT: {wsStatus}
                </span>
              </div>
            </div>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search incidents…"
              className="w-72 max-w-[45vw] rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm outline-none focus:ring-slate-700"
            />

            <select
              value={sevFilter}
              onChange={(e) => setSevFilter(e.target.value)}
              className="rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
            >
              <option value="all">Severity: All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
            >
              <option value="all">Status: All</option>
              <option value="open">Open</option>
              <option value="triaged">Triaged</option>
              <option value="closed">Closed</option>
            </select>

            <button
              onClick={doRebuild}
              className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
            >
              Rebuild
            </button>

            <button
              onClick={loadAll}
              className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
            >
              Refresh
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card title="Open Incidents" value={kpis.open} sub="Needs triage" />
          <Card title="Critical Incidents" value={kpis.critical} sub="Highest priority" />
          <Card title="Average Risk" value={kpis.avgRisk.toFixed(1)} sub="Across all incidents" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <Section
            title={`Incidents (${filtered.length})`}
            right={<span className="text-xs text-slate-400">{loading ? "Loading…" : "Ready"}</span>}
          >
            <div className="overflow-auto rounded-xl ring-1 ring-slate-800">
              <table className="w-full text-sm">
                <thead className="bg-slate-900/60 text-slate-300">
                  <tr>
                    <th className="text-left px-3 py-2 font-semibold">Severity</th>
                    <th className="text-left px-3 py-2 font-semibold">Title</th>
                    <th className="text-left px-3 py-2 font-semibold">Status</th>
                    <th className="text-right px-3 py-2 font-semibold">Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((i) => (
                    <tr
                      key={i.id}
                      onClick={() => setSelectedId(i.id)}
                      className={cx(
                        "cursor-pointer border-t border-slate-800 hover:bg-slate-800/25",
                        selectedId === i.id ? "bg-slate-800/35" : ""
                      )}
                    >
                      <td className="px-3 py-2">
                        <SeverityBadge sev={i.severity} />
                      </td>
                      <td className="px-3 py-2">
                        <div className="font-semibold">{i.title}</div>
                        <div className="text-xs text-slate-400">
                          #{i.id} • Confidence {Number(i.confidence || 0).toFixed(2)}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <StatusPill status={i.status} />
                      </td>
                      <td className="px-3 py-2 text-right font-semibold">
                        {Number(i.risk_score || 0).toFixed(1)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!filtered.length && <div className="mt-3 text-sm text-slate-400">No incidents yet. Click Rebuild.</div>}
          </Section>

          <Section
            title={selected ? `Incident #${selected.id}` : "Incident Detail"}
            right={
              selected ? (
                <div className="flex items-center gap-2">
                  <SeverityBadge sev={selected.severity} />
                  <StatusPill status={selected.status} />
                </div>
              ) : null
            }
          >
            {!selected ? (
              <div className="text-sm text-slate-400">Select an incident on the left.</div>
            ) : (
              <div className="space-y-4">
                <div>
                  <div className="text-lg font-semibold">{selected.title}</div>
                  <div className="text-xs text-slate-400">
                    Confidence {Number(selected.confidence || 0).toFixed(2)} • Verdict{" "}
                    {selected.analyst_verdict || "unknown"}
                  </div>
                </div>

                <div>
                  <div className="text-xs text-slate-400 mb-2">Risk Score</div>
                  <RiskBar value={selected.risk_score} />
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <TabButton active={tab === "summary"} onClick={() => setTab("summary")}>Summary</TabButton>
                  <TabButton active={tab === "timeline"} onClick={() => setTab("timeline")}>Timeline</TabButton>
                  <TabButton active={tab === "mitre"} onClick={() => setTab("mitre")}>MITRE</TabButton>
                  <TabButton active={tab === "iocs"} onClick={() => setTab("iocs")}>IoCs</TabButton>
                  <TabButton active={tab === "queries"} onClick={() => setTab("queries")}>Queries</TabButton>
                  <TabButton active={tab === "checklist"} onClick={() => setTab("checklist")}>Checklist</TabButton>
                  <TabButton active={tab === "playbook"} onClick={() => setTab("playbook")}>Playbook</TabButton>
                  <TabButton active={tab === "notes"} onClick={() => setTab("notes")}>Notes</TabButton>
                  <TabButton active={tab === "export"} onClick={() => setTab("export")}>Export</TabButton>
                </div>

                {tab === "summary" && (
                  <div className="rounded-xl bg-slate-950/40 ring-1 ring-slate-800 p-3 whitespace-pre-wrap text-sm text-slate-200">
                    {detail?.summary || selected.summary}
                  </div>
                )}

                {tab === "timeline" && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="text-sm font-semibold">Event Timeline</div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-slate-400">Sort</span>
                        <select
                          value={timelineOrder}
                          onChange={(e) => setTimelineOrder(e.target.value)}
                          className="rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
                        >
                          <option value="oldest">Oldest → Newest</option>
                          <option value="newest">Newest → Oldest</option>
                        </select>
                      </div>
                    </div>

                    <TimelinePanel alerts={detailAlerts} order={timelineOrder} />
                  </div>
                )}

                {tab === "mitre" && <MitrePanel mitre={mitreRows} />}

                {tab === "iocs" && <IocPanel alerts={detailAlerts} />}

                {tab === "queries" && <QueriesPanel iocs={iocs} />}

                {tab === "checklist" && (
                  <div className="space-y-3">
                    <div className="rounded-2xl bg-slate-950/30 ring-1 ring-slate-800 p-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-sm font-semibold">Triage Progress</div>
                          <div className="mt-1 text-xs text-slate-400">
                            Auto-checks happen when data exists (IoCs/MITRE/timeline). You can tick the rest during investigation.
                          </div>
                        </div>
                        <div className="text-xs text-slate-300">{checklistDoneCount}/9 complete</div>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <ChecklistRow checked={autoChecks.scope} title="Confirm scope and affected asset(s)" subtitle="" badge="auto" disabled />
                      <ChecklistRow checked={autoChecks.validate} title="Validate signal (true positive vs false positive)" subtitle="" badge="auto" disabled />
                      <ChecklistRow
                        checked={autoChecks.iocs}
                        title="Extract IoCs (IPs, users, hosts, hashes if any)"
                        subtitle={`Found: ${iocs.ips.length} IPs • ${iocs.users.length} users • ${iocs.hosts.length} hosts • ${iocs.alertTypes.length} alert types`}
                        badge="auto"
                        disabled
                      />
                      <ChecklistRow
                        checked={autoChecks.mitre}
                        title="Check MITRE mapping (tactic/technique)"
                        subtitle={autoChecks.mitre ? "MITRE techniques attached ✅" : "No MITRE attached"}
                        badge="auto"
                        disabled
                      />
                      <ChecklistRow
                        checked={autoChecks.timeline}
                        title="Review timeline for sequence of events"
                        subtitle={autoChecks.timeline ? `${detailAlerts.length} events available` : "No events yet"}
                        badge="auto"
                        disabled
                      />

                      <ChecklistRow
                        checked={manualChecks.contain}
                        title="Contain threat (block IP / disable user / isolate host)"
                        subtitle=""
                        badge="manual"
                        onToggle={() => setManualChecks((p) => ({ ...p, contain: !p.contain }))}
                      />
                      <ChecklistRow
                        checked={manualChecks.eradicate}
                        title="Eradicate (remove persistence, rotate creds)"
                        subtitle=""
                        badge="manual"
                        onToggle={() => setManualChecks((p) => ({ ...p, eradicate: !p.eradicate }))}
                      />
                      <ChecklistRow
                        checked={manualChecks.recover}
                        title="Recovery + monitoring (watch for recurrence)"
                        subtitle=""
                        badge="manual"
                        onToggle={() => setManualChecks((p) => ({ ...p, recover: !p.recover }))}
                      />
                      <ChecklistRow
                        checked={manualChecks.document}
                        title="Document outcome in analyst notes and close/triage"
                        subtitle=""
                        badge="manual"
                        onToggle={() => setManualChecks((p) => ({ ...p, document: !p.document }))}
                      />
                    </div>

                    <div className="flex items-center gap-2 pt-2">
                      <button
                        onClick={() => {
                          resetChecklist();
                          addLog("Reset Checklist", "");
                        }}
                        className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
                      >
                        Reset
                      </button>
                      <button
                        onClick={copyChecklist}
                        className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
                      >
                        Copy checklist
                      </button>
                    </div>

                    <div className="text-xs text-slate-500">
                      Persistence: Manual checklist is saved per-incident locally (refresh won’t wipe it).
                    </div>
                  </div>
                )}

                {tab === "playbook" && (
                  <div className="space-y-3">
                    {!playbook.length ? (
                      <div className="text-sm text-slate-400">No playbook steps available.</div>
                    ) : (
                      <>
                        <div className="text-sm text-slate-300">Recommended response actions:</div>
                        <div className="space-y-2">
                          {playbook.map((s) => (
                            <div key={s.action} className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
                              <div className="flex items-center justify-between">
                                <div className="font-semibold">{s.action}</div>
                                <div className="text-xs text-slate-400">risk: {s.risk}</div>
                              </div>
                              <div className="mt-1 text-sm text-slate-300">{s.impact}</div>
                            </div>
                          ))}
                        </div>

                        <div className="flex items-center gap-2 pt-2">
                          <select
                            value={action}
                            onChange={(e) => setAction(e.target.value)}
                            className="flex-1 rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
                          >
                            {playbook.map((s) => (
                              <option key={s.action} value={s.action}>
                                {s.action}
                              </option>
                            ))}
                          </select>
                          <button
                            onClick={runAction}
                            className="rounded-xl bg-emerald-500/15 hover:bg-emerald-500/20 ring-1 ring-emerald-500/30 px-3 py-2 text-sm font-semibold text-emerald-200"
                          >
                            Simulate
                          </button>
                        </div>

                        <div className="text-xs text-slate-500">
                          Persistence: Simulation actions are logged and saved per-incident locally.
                        </div>
                      </>
                    )}
                  </div>
                )}

                {tab === "notes" && (
                  <div className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      <div>
                        <div className="text-xs text-slate-400 mb-1">Verdict</div>
                        <select
                          value={verdict}
                          onChange={(e) => setVerdict(e.target.value)}
                          className="w-full rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
                        >
                          <option value="unknown">unknown</option>
                          <option value="true_positive">true_positive</option>
                          <option value="false_positive">false_positive</option>
                        </select>
                      </div>
                      <div>
                        <div className="text-xs text-slate-400 mb-1">Status</div>
                        <select
                          value={status}
                          onChange={(e) => setStatus(e.target.value)}
                          className="w-full rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm"
                        >
                          <option value="open">open</option>
                          <option value="triaged">triaged</option>
                          <option value="closed">closed</option>
                        </select>
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-400 mb-1">Analyst notes</div>
                      <textarea
                        value={notes}
                        onChange={(e) => setNotes(e.target.value)}
                        rows={7}
                        className="w-full rounded-xl bg-slate-900/60 ring-1 ring-slate-800 px-3 py-2 text-sm outline-none focus:ring-slate-700"
                        placeholder="Add investigation notes, IoCs, decisions…"
                      />
                      <div className="mt-2 text-xs text-slate-500">
                        Persistence: Your note edits are saved per-incident locally (draft) until you click Save.
                      </div>
                    </div>

                    <button
                      onClick={saveCase}
                      className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
                    >
                      Save
                    </button>

                    <div className="pt-3">
                      <div className="flex items-center justify-between mb-2">
                        <div className="text-sm font-semibold">Action Log</div>
                        <button
                          onClick={() => {
                            if (!selectedId) return;
                            if (confirm("Clear action log for this incident?")) {
                              setActionLogs([]);
                              addLog("Clear Action Log", "");
                            }
                          }}
                          className="text-xs px-2 py-1 rounded-lg bg-white/10 hover:bg-white/15 ring-1 ring-white/10"
                        >
                          Clear
                        </button>
                      </div>

                      {!actionLogs.length ? (
                        <div className="text-sm text-slate-400">No actions recorded yet.</div>
                      ) : (
                        <div className="space-y-2">
                          {actionLogs.slice(0, 20).map((l, idx) => (
                            <div key={`${l.ts}-${idx}`} className="rounded-xl bg-slate-950/35 ring-1 ring-slate-800 p-3">
                              <div className="flex items-center justify-between">
                                <div className="font-semibold">{l.action}</div>
                                <div className="text-xs text-slate-400">{fmtTime(l.ts)}</div>
                              </div>
                              {l.meta ? <div className="mt-1 text-sm text-slate-300">{l.meta}</div> : null}
                            </div>
                          ))}
                        </div>
                      )}

                      <div className="mt-2 text-xs text-slate-500">
                        Persistence: Action log is stored per-incident in localStorage (refresh won’t wipe it).
                      </div>
                    </div>
                  </div>
                )}

                {tab === "export" && (
                  <div className="space-y-3">
                    <div className="text-sm text-slate-300">Export incident artifacts for demos, audits, and handoffs.</div>

                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={downloadExport}
                        className="rounded-xl bg-white/10 hover:bg-white/15 ring-1 ring-white/10 px-3 py-2 text-sm font-semibold"
                      >
                        Download Incident JSON
                      </button>

                      <button
                        onClick={downloadInvestigatorPack}
                        className="rounded-xl bg-emerald-500/15 hover:bg-emerald-500/20 ring-1 ring-emerald-500/30 px-3 py-2 text-sm font-semibold text-emerald-200"
                      >
                        Download Investigator Pack
                      </button>
                    </div>

                    <div className="text-xs text-slate-500">
                      Investigator Pack includes summary, timeline, MITRE, IoCs, queries, checklist, and action log.
                    </div>
                  </div>
                )}
              </div>
            )}
          </Section>
        </div>

        <div className="text-xs text-slate-500">
          Tip: Keep backend running at <span className="text-slate-300">http://localhost:8000</span>.
        </div>
      </div>
    </div>
  );
}
