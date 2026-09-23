import AttackMap, { GeoIPLookup } from "./AttackMap";
import { useEffect, useState, useCallback, type ReactNode } from "react";
import { NavLink, Link, useLocation } from "react-router-dom";
import {
  Shield,
  LayoutDashboard,
  Terminal,
  Radar,
  Network,
  Users,
  History,
  Server,
  ChevronRight,
  ArrowUpRight,
  ArrowDownToLine,
  RefreshCw,
  Cpu,
  MemoryStick,
  HardDrive,
  Clock3,
  CircleHelp,
  X,
  Search,
  Check,
  Info,
  TriangleAlert,
  Menu,
  Activity,
  LockKeyhole,
  Globe,
  SlidersHorizontal,
} from "lucide-react";
import {
  useApi,
  refreshAll,
  bytes,
  duration,
  time,
  title,
  type Stats,
  type Health,
  type Score,
  type SSH,
  type Scans,
  type Event,
  type EventList,
  type Port,
  type User,
  type Monitor,
  type Sample,
} from "./api";

const navigation = [
  ["/", "Overview", LayoutDashboard],
  ["/ssh", "SSH Security", Terminal],
  ["/network", "Network Scans", Radar],
  ["/attack-map", "Attack Map", Globe],
  ["/ports", "Open Ports", Network],
  ["/users", "System Users", Users],
  ["/activity", "Activity Log", History],
] as const;
function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
function State({ status }: { status?: Monitor }) {
  return (
    <Badge tone={status?.state === "active" ? "green" : "amber"}>
      <span className="status-dot" />
      {status?.state === "active" ? "Active" : "Unavailable"}
    </Badge>
  );
}
function Empty({
  children = "No events recorded yet. New activity will appear here.",
}: {
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <Shield size={24} />
      <strong>Nothing to report</strong>
      <p>{children}</p>
    </div>
  );
}
function ErrorBox({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="notice error" role="alert">
      <TriangleAlert size={18} />
      <div>
        <strong>Couldn’t refresh this data</strong>
        <p>{message} Last received values may be stale.</p>
      </div>
      {onRetry && <button onClick={onRetry}>Retry</button>}
    </div>
  );
}
function Loading() {
  return (
    <div className="loading" role="status">
      <RefreshCw size={18} className="spin" /> Fetching server data…
    </div>
  );
}
function Panel({
  title: heading,
  extra,
  children,
  className = "",
}: {
  title: ReactNode;
  extra?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-heading">
        <h2>{heading}</h2>
        {extra}
      </div>
      {children}
    </section>
  );
}
function EventTable({
  items,
  onSelect,
  compact = false,
}: {
  items: Event[];
  onSelect: (event: Event) => void;
  compact?: boolean;
}) {
  return items.length === 0 ? (
    <Empty />
  ) : (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Event</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Time</th>
            {!compact && <th>Origin</th>}
            <th>
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((event) => (
            <tr key={event.id}>
              <td>
                <button className="event-title" onClick={() => onSelect(event)}>
                  <span
                    className={`event-symbol ${event.severity.toLowerCase()}`}
                  >
                    {event.type.includes("SSH") ? (
                      <Terminal size={15} />
                    ) : event.category === "Network" ? (
                      <Radar size={15} />
                    ) : (
                      <Activity size={15} />
                    )}
                  </span>
                  {title(event.type)}
                </button>
              </td>
              <td className="mono muted">
                {event.source_ip || "Local system"}
              </td>
              <td>
                <Badge
                  tone={
                    ["HIGH", "CRITICAL"].includes(event.severity)
                      ? "red"
                      : event.severity === "MEDIUM"
                        ? "amber"
                        : event.severity === "LOW"
                          ? "blue"
                          : "green"
                  }
                >
                  {event.severity.toLowerCase()}
                </Badge>
              </td>
              <td
                className="mono muted"
                title={new Date(event.timestamp * 1000).toLocaleString()}
              >
                {time(event.timestamp)}
              </td>
              {!compact && (
                <td>
                  <Badge>Observed</Badge>
                </td>
              )}
              <td>
                <button
                  className="icon-button"
                  aria-label={`View event ${event.id}`}
                  onClick={() => onSelect(event)}
                >
                  <ChevronRight size={15} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function Chart({
  history,
  series = "cpu",
  large = false,
}: {
  history: Sample[];
  series?: "cpu" | "ram" | "disk";
  large?: boolean;
}) {
  const width = 600,
    height = large ? 140 : 46;
  if (history.length < 2)
    return (
      <div className={`chart-wait ${large ? "large" : ""}`}>
        Collecting history…
      </div>
    );
  const span = Math.max(1, history.at(-1)!.timestamp - history[0].timestamp);
  const points = history
    .map(
      (p) =>
        `${((p.timestamp - history[0].timestamp) / span) * width},${height - 5 - (p[series] / 100) * (height - 10)}`,
    )
    .join(" ");
  return (
    <svg
      className={`chart ${series}`}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={`${series.toUpperCase()} usage history, current ${history.at(-1)![series].toFixed(1)} percent`}
    >
      {large &&
        [25, 50, 75].map((n) => (
          <line
            key={n}
            x1="0"
            x2={width}
            y1={height - (n / 100) * (height - 10) - 5}
            y2={height - (n / 100) * (height - 10) - 5}
            className="chart-grid"
          />
        ))}
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth={large ? 2 : 1.6}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
function MonitorCard({
  kind,
  status,
  count,
  caption,
  to,
}: {
  kind: "ssh" | "network";
  status?: Monitor;
  count?: number;
  caption: string;
  to: string;
}) {
  const Icon = kind === "ssh" ? Terminal : Radar;
  return (
    <Link to={to} className="monitor-card">
      <div className="monitor-top">
        <span className="monitor-icon">
          <Icon size={21} />
        </span>
        <State status={status} />
      </div>
      <h3>
        {kind === "ssh" ? "SSH protection" : "Network monitor"}
        <ArrowUpRight size={17} />
      </h3>
      <p>
        {kind === "ssh"
          ? "Authentication activity & brute-force detection"
          : "Passive monitoring of inbound connections"}
      </p>
      <div className="monitor-bottom">
        <strong>
          {count ?? "—"} <span>{caption}</span>
        </strong>
        <span>Last 24 hours</span>
      </div>
    </Link>
  );
}
function Overview({
  health,
  stats,
  onSelect,
}: {
  health?: Health;
  stats?: Stats;
  onSelect: (e: Event) => void;
}) {
  const score = useApi<Score>("/security-score"),
    ssh = useApi<SSH>("/ssh"),
    scans = useApi<Scans>("/scans"),
    events = useApi<EventList>("/events/recent"),
    ports = useApi<{ items: Port[] }>("/ports");
  const [showScore, setShowScore] = useState(false),
    [series, setSeries] = useState<"cpu" | "ram" | "disk">("cpu");
  return (
    <>
      <div className="overview-top">
        <section className="score-panel">
          <div className="score-copy">
            <div className="score-title">
              <Shield size={17} />
              <h2>VPSentry Security Score</h2>
              <button
                className="icon-button"
                aria-label="Explain security score"
                aria-expanded={showScore}
                onClick={() => setShowScore(!showScore)}
              >
                <CircleHelp size={15} />
              </button>
            </div>
            <div className="score-value">
              {score.data?.score ?? "—"}
              <span>/ 100</span>
              <Badge
                tone={score.data && score.data.score >= 75 ? "green" : "amber"}
              >
                {score.data?.label ?? "Loading"}
              </Badge>
            </div>
            <p>Based on observed activity in the last 24 hours.</p>
            <span className="coverage">
              <Info size={13} />
              {!score.data
                ? "Checking monitoring coverage…"
                : score.data.unknown.length
                  ? "Coverage is partial. Review monitoring status."
                  : "All configured monitors reporting."}
            </span>
          </div>
          <div className="score-mark" aria-hidden="true">
            <Shield size={86} strokeWidth={1} />
            <Check size={28} />
          </div>
          {showScore && (
            <div className="score-explanation">
              <p>{score.data?.description}</p>
              <p>
                Firewall: {score.data?.firewall ?? "unknown"}. Configured rules
                are not an assessment of their effectiveness.
              </p>
              {score.data?.deductions.map((d) => (
                <p key={d.reason}>
                  −{d.points} · {d.reason}
                </p>
              ))}
              {score.data?.unknown.map((s) => (
                <p key={s}>{s}</p>
              ))}
            </div>
          )}
          {score.error && <ErrorBox message={score.error} />}
        </section>
        <div className="host-summary">
          <span className="host-icon">
            <Server size={23} />
          </span>
          <div>
            <h2>{stats?.hostname ?? "Connecting to server"}</h2>
            <p>
              {stats
                ? `${stats.platform} · ${stats.cores} CPU cores`
                : "Waiting for host information"}
            </p>
          </div>
          <div className="host-footer">
            <span>
              <span
                className={`status-dot ${health?.sampling_ok ? "green" : "amber"}`}
              />
              {health?.sampling_ok
                ? "Telemetry connected"
                : "Telemetry pending"}
            </span>
            <span className="mono">:{health?.port ?? 8787}</span>
          </div>
        </div>
      </div>
      <div className="metrics">
        <Metric
          label="CPU usage"
          icon={<Cpu size={16} />}
          value={stats ? `${stats.cpu.toFixed(1)}` : "—"}
          unit="%"
          description={
            stats
              ? `Load ${stats.load.map((n) => n.toFixed(2)).join(" / ")}`
              : "Waiting for sample"
          }
          history={stats?.history}
        />
        <Metric
          label="Memory"
          icon={<MemoryStick size={16} />}
          value={stats ? stats.ram.percent.toFixed(1) : "—"}
          unit="%"
          description={
            stats
              ? `${bytes(stats.ram.used)} of ${bytes(stats.ram.total)}`
              : "Waiting for sample"
          }
          history={stats?.history}
          series="ram"
        />
        <Metric
          label="Disk storage"
          icon={<HardDrive size={16} />}
          value={stats ? stats.disk.percent.toFixed(1) : "—"}
          unit="%"
          description={
            stats
              ? `${bytes(stats.disk.used)} of ${bytes(stats.disk.total)}`
              : "Waiting for sample"
          }
          history={stats?.history}
          series="disk"
        />
        <Metric
          label="System uptime"
          icon={<Clock3 size={16} />}
          value={stats ? duration(stats.uptime) : "—"}
          description="Since the last server restart"
        />
      </div>
      <div className="dashboard-middle">
        <Panel
          title="Resource activity"
          extra={<span className="muted small">Up to 1 hour</span>}
        >
          <div className="chart-tabs">
            {(["cpu", "ram", "disk"] as const).map((s) => (
              <button
                key={s}
                className={series === s ? "selected" : ""}
                onClick={() => setSeries(s)}
              >
                <span className={`legend ${s}`} />
                {s === "ram" ? "Memory" : s.toUpperCase()}
              </button>
            ))}
            <span className="muted small">0–100%</span>
          </div>
          <div className="large-chart">
            <Chart history={stats?.history ?? []} series={series} large />
            <div className="chart-axis">
              <span>
                {stats?.history.length
                  ? time(stats.history[0].timestamp)
                  : "Awaiting samples"}
              </span>
              <span>Now</span>
            </div>
          </div>
        </Panel>
        <div className="monitor-stack">
          <MonitorCard
            kind="ssh"
            status={health?.monitors.ssh}
            count={ssh.data?.attacks_24h}
            caption="attacks detected"
            to="/ssh"
          />
          <MonitorCard
            kind="network"
            status={health?.monitors.network}
            count={scans.data?.scans_24h}
            caption="scans detected"
            to="/network"
          />
        </div>
      </div>
      <AttackMap compact />
      <div className="dashboard-bottom">
        <Panel
          title="Recent security events"
          extra={
            <Link className="text-link" to="/activity">
              View all events <ArrowUpRight size={14} />
            </Link>
          }
        >
          {events.error ? (
            <ErrorBox message={events.error} onRetry={events.refresh} />
          ) : events.data ? (
            <EventTable items={events.data.items} onSelect={onSelect} compact />
          ) : (
            <Loading />
          )}
        </Panel>
        <Panel
          title="Listening ports"
          extra={
            <Link
              to="/ports"
              className="text-link"
              aria-label="View all listening ports"
            >
              <ArrowUpRight size={16} />
            </Link>
          }
        >
          {ports.data?.items.length ? (
            <div className="port-list">
              {ports.data.items.slice(0, 4).map((p, i) => (
                <div key={i}>
                  <span className="port-number mono">{p.port}</span>
                  <span>
                    <strong>{p.process || p.service}</strong>
                    <small>
                      {p.protocol} · {p.address}
                    </small>
                  </span>
                  <span className="status-dot green" />
                </div>
              ))}
              <Link to="/ports" className="all-ports">
                View all {ports.data.items.length} listeners{" "}
                <ChevronRight size={14} />
              </Link>
            </div>
          ) : (
            <div className="quiet-empty">
              <Network size={22} />
              <p>
                {health?.monitors.ports.state === "active"
                  ? "No listening ports found."
                  : "Port visibility is unavailable."}
              </p>
              <Link to="/ports" className="text-link">
                Review coverage <ChevronRight size={14} />
              </Link>
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
function Metric({
  label,
  icon,
  value,
  unit,
  description,
  history,
  series = "cpu",
}: {
  label: string;
  icon: ReactNode;
  value: string;
  unit?: string;
  description: string;
  history?: Sample[];
  series?: "cpu" | "ram" | "disk";
}) {
  return (
    <section className="metric">
      <div className="metric-label">
        {label}
        {icon}
      </div>
      <div className="metric-value">
        {value}
        <span>{unit}</span>
      </div>
      <p>{description}</p>
      {history ? (
        <Chart history={history} series={series} />
      ) : (
        <div className="uptime-line">
          {value === "—" ? (
            "Waiting for sample"
          ) : (
            <>
              <span className="status-dot green" />
              Host uptime
            </>
          )}
        </div>
      )}
    </section>
  );
}
function MonitorPage({
  kind,
  health,
  onSelect,
}: {
  kind: "ssh" | "network";
  health?: Health;
  onSelect: (e: Event) => void;
}) {
  const ssh = useApi<SSH>("/ssh"),
    scans = useApi<Scans>("/scans"),
    events = useApi<EventList>(
      `/events?category=${kind === "ssh" ? "SSH" : "Network"}`,
    );
  const status = health?.monitors[kind],
    details = kind === "ssh" ? ssh.data : scans.data;
  return (
    <>
      <div className="notice">
        <Info size={19} />
        <div>
          <strong>
            {kind === "ssh"
              ? "Observation without intervention"
              : "Passive inbound detection"}
          </strong>
          <p>
            {kind === "ssh"
              ? "VPSentry detects suspicious logins. It never changes SSH configuration or blocks an address."
              : "Only traffic arriving at this VPS is observed. No external addresses are scanned."}
          </p>
        </div>
        <State status={status} />
      </div>
      <div className="three-metrics">
        <div>
          <span>
            {kind === "ssh" ? "Brute-force incidents" : "Port-scan incidents"}
          </span>
          <strong>
            {kind === "ssh"
              ? (ssh.data?.attacks_24h ?? "—")
              : (scans.data?.scans_24h ?? "—")}
          </strong>
          <small>Last 24 hours</small>
        </div>
        <div>
          <span>
            {kind === "ssh" ? "Failed logins" : "Unique-port threshold"}
          </span>
          <strong>
            {kind === "ssh"
              ? (ssh.data?.failed_24h ?? "—")
              : (scans.data?.threshold ?? "—")}
          </strong>
          <small>
            {kind === "ssh" ? "Last 24 hours" : "Ports per source address"}
          </small>
        </div>
        <div>
          <span>
            {kind === "ssh" ? "Successful logins" : "Detection window"}
          </span>
          <strong>
            {kind === "ssh"
              ? (ssh.data?.successful_24h ?? "—")
              : `${scans.data?.window ?? "—"}s`}
          </strong>
          <small>{kind === "ssh" ? "Last 24 hours" : "Sliding window"}</small>
        </div>
      </div>
      <Panel
        title="Monitor configuration"
        extra={<SlidersHorizontal size={17} />}
      >
        <div className="config-row">
          <div>
            <span>Detection rule</span>
            <strong>
              {details?.threshold ?? "—"}{" "}
              {kind === "ssh" ? "failed attempts" : "different ports"} within{" "}
              {details?.window ?? "—"} seconds
            </strong>
          </div>
          <div>
            <span>Source status</span>
            <strong>{status?.message ?? "Waiting for monitor"}</strong>
          </div>
        </div>
      </Panel>
      <Panel
        title={
          kind === "ssh"
            ? "SSH authentication events"
            : "Network scan incidents"
        }
        extra={<span className="muted small">Latest 50 events</span>}
      >
        {events.error && (
          <ErrorBox message={events.error} onRetry={events.refresh} />
        )}{" "}
        {events.data ? (
          <EventTable items={events.data.items} onSelect={onSelect} />
        ) : (
          <Loading />
        )}
      </Panel>
    </>
  );
}
function PortsPage({ health }: { health?: Health }) {
  const ports = useApi<{ items: Port[] }>("/ports");
  const [q, setQ] = useState("");
  const list =
    ports.data?.items.filter((p) =>
      `${p.port} ${p.protocol} ${p.process} ${p.service} ${p.address}`
        .toLowerCase()
        .includes(q.toLowerCase()),
    ) ?? [];
  return (
    <>
      <div className="notice">
        <Network size={20} />
        <div>
          <strong>Live listening sockets</strong>
          <p>
            {health?.monitors.ports.message ?? "Inspecting host sockets"} · No
            vulnerability scanning is performed.
          </p>
        </div>
        <State status={health?.monitors.ports} />
      </div>
      <Panel
        title="Open ports"
        extra={<Badge>{ports.data?.items.length ?? 0} listeners</Badge>}
      >
        <div className="table-toolbar">
          <SearchField
            value={q}
            onChange={setQ}
            placeholder="Find a port, address or process…"
          />
        </div>
        {ports.error && (
          <ErrorBox message={ports.error} onRetry={ports.refresh} />
        )}{" "}
        {!ports.data ? (
          <Loading />
        ) : list.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Listening address</th>
                  <th>Process / service</th>
                  <th>Reachability</th>
                </tr>
              </thead>
              <tbody>
                {list.map((p, i) => (
                  <tr key={i}>
                    <td className="mono bright">{p.port}</td>
                    <td>
                      <Badge>{p.protocol}</Badge>
                    </td>
                    <td className="mono muted">{p.address}</td>
                    <td>
                      {p.process || p.service}
                      <small className="cell-note">
                        {p.process
                          ? "Process name"
                          : "Service hint; process unavailable"}
                      </small>
                    </td>
                    <td>
                      <Badge tone={p.exposure === "Local" ? "neutral" : "blue"}>
                        {p.exposure === "Local" ? (
                          <LockKeyhole size={12} />
                        ) : (
                          <Globe size={12} />
                        )}{" "}
                        {p.exposure}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>
            {q
              ? "No listeners match your search."
              : health?.monitors.ports.state === "active"
                ? "No listening sockets found."
                : "Host permissions do not currently allow port visibility."}
          </Empty>
        )}
      </Panel>
      <p className="page-note">
        Network reachability describes the bind address. Firewall rules may
        still restrict access.
      </p>
    </>
  );
}
function UsersPage() {
  const users = useApi<{ items: User[] }>("/users", 30000);
  const [q, setQ] = useState("");
  const list =
    users.data?.items.filter(
      (u) => u.username.includes(q) || String(u.uid).includes(q),
    ) ?? [];
  return (
    <>
      <div className="notice">
        <LockKeyhole size={20} />
        <div>
          <strong>Read-only account inventory</strong>
          <p>
            Root and local users with UID 1000–65533. Shell capability does not
            indicate SSH access or password status.
          </p>
        </div>
        <Badge>Read only</Badge>
      </div>
      <Panel
        title="System users"
        extra={<Badge>{users.data?.items.length ?? 0} accounts</Badge>}
      >
        <div className="table-toolbar">
          <SearchField
            value={q}
            onChange={setQ}
            placeholder="Find a username or UID…"
          />
        </div>
        {users.error && (
          <ErrorBox message={users.error} onRetry={users.refresh} />
        )}{" "}
        {!users.data ? (
          <Loading />
        ) : list.length ? (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>UID</th>
                  <th>Home directory</th>
                  <th>Login shell</th>
                  <th>Interactive shell</th>
                </tr>
              </thead>
              <tbody>
                {list.map((u) => (
                  <tr key={u.uid}>
                    <td className="bright">
                      <span className="user-avatar">
                        <Users size={14} />
                      </span>
                      {u.username}
                    </td>
                    <td className="mono muted">{u.uid}</td>
                    <td className="mono muted">{u.home}</td>
                    <td className="mono muted">{u.shell || "None"}</td>
                    <td>
                      <Badge tone={u.interactive ? "green" : "neutral"}>
                        {u.interactive ? "Available" : "Disabled"}
                      </Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>No matching local users.</Empty>
        )}
      </Panel>
    </>
  );
}
function SearchField({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}) {
  return (
    <label className="search-field">
      <Search size={16} />
      <span className="sr-only">{placeholder}</span>
      <input
        aria-label={placeholder}
        value={value}
        maxLength={128}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {value && (
        <button
          className="icon-button"
          aria-label="Clear search"
          onClick={() => onChange("")}
        >
          <X size={14} />
        </button>
      )}
    </label>
  );
}
function ActivityPage({ onSelect }: { onSelect: (e: Event) => void }) {
  const [category, setCategory] = useState("All"),
    [severity, setSeverity] = useState(""),
    [q, setQ] = useState(""),
    [offset, setOffset] = useState(0);
  const params = new URLSearchParams({
    limit: "20",
    offset: String(offset),
    q,
  });
  if (category !== "All") params.set("category", category);
  if (severity) params.set("severity", severity);
  const events = useApi<EventList>("/events?" + params.toString());
  useEffect(() => setOffset(0), [category, severity, q]);
  function exportEvents() {
    if (!events.data) return;
    const blob = new Blob([JSON.stringify(events.data.items, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "vpsentry-events.json";
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <>
      <Panel
        title="Event history"
        extra={
          <button
            className="subtle-button"
            onClick={exportEvents}
            disabled={!events.data?.items.length}
          >
            <ArrowDownToLine size={15} />
            Export this page
          </button>
        }
      >
        <div className="activity-filters">
          <div className="filter-tabs" aria-label="Event category">
            {["All", "SSH", "Network", "System"].map((c) => (
              <button
                key={c}
                aria-pressed={category === c}
                className={category === c ? "selected" : ""}
                onClick={() => setCategory(c)}
              >
                {c}
              </button>
            ))}
          </div>
          <div className="filter-inputs">
            <SearchField
              value={q}
              onChange={setQ}
              placeholder="Search events or IP…"
            />
            <select
              aria-label="Filter severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>
        {events.error && (
          <ErrorBox message={events.error} onRetry={events.refresh} />
        )}{" "}
        {events.data ? (
          <EventTable items={events.data.items} onSelect={onSelect} />
        ) : (
          <Loading />
        )}
        <div className="pagination">
          <span>
            {events.data?.total
              ? `${offset + 1}–${Math.min(offset + 20, events.data.total)} of ${events.data.total} events`
              : "0 events"}
          </span>
          <div>
            <button
              disabled={offset === 0 || events.loading}
              onClick={() => setOffset(Math.max(0, offset - 20))}
            >
              Previous
            </button>
            <button
              disabled={
                !events.data ||
                offset + 20 >= events.data.total ||
                events.loading
              }
              onClick={() => setOffset(offset + 20)}
            >
              Next
            </button>
          </div>
        </div>
      </Panel>
    </>
  );
}
function EventDetails({
  event,
  onClose,
}: {
  event: Event;
  onClose: () => void;
}) {
  useEffect(() => {
    const old = document.activeElement as HTMLElement;
    const close = document.getElementById("close-event");
    close?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => {
      window.removeEventListener("keydown", handler);
      old?.focus();
    };
  }, [onClose]);
  return (
    <aside className="event-details" aria-label="Event details">
      <div className="panel-heading">
        <h2>Event #{event.id}</h2>
        <button
          id="close-event"
          className="icon-button"
          aria-label="Close event details"
          onClick={onClose}
        >
          <X size={19} />
        </button>
      </div>
      <h3>{title(event.type)}</h3>
      <p>{event.description}</p>
      <dl>
        <dt>Recorded</dt>
        <dd>{new Date(event.timestamp * 1000).toLocaleString()}</dd>
        <dt>Source</dt>
        <dd className="mono">{event.source_ip || "Local system"}</dd>
        <dt>Severity</dt>
        <dd>{event.severity}</dd>
        <dt>Origin</dt>
        <dd>Observed on this host</dd>
      </dl>
      {event.source_ip && <GeoIPLookup ip={event.source_ip} />}
      <h4>Structured details</h4>
      <pre>{JSON.stringify(event.details, null, 2)}</pre>
    </aside>
  );
}
export default function App() {
  const location = useLocation(),
    health = useApi<Health>("/health"),
    stats = useApi<Stats>("/stats");
  const [menu, setMenu] = useState(false),
    [selected, setSelected] = useState<Event | null>(null);
  const [testAlert, setTestAlert] = useState(false);
  const hasLiveAttack = !!health.data?.active_alerts?.total;
  useEffect(() => {
    if (hasLiveAttack) setTestAlert(false);
    if (!testAlert) return;
    const timer = window.setTimeout(() => setTestAlert(false), 20000);
    return () => window.clearTimeout(timer);
  }, [testAlert, hasLiveAttack]);
  const closeDetails = useCallback(() => setSelected(null), []);
  const page =
    navigation.find((n) => n[0] === location.pathname)?.[1] ?? "Page not found";
  const names: Record<string, string> = {
    "/": "Server overview",
    "/ssh": "SSH security",
    "/network": "Network scans",
    "/attack-map": "Attack map",
    "/ports": "Open ports",
    "/users": "System users",
    "/activity": "Activity log",
  };
  const subtitles: Record<string, string> = {
    "/": "A clear view of your server’s health and security.",
    "/ssh": "Know who is connecting. Spot suspicious authentication activity.",
    "/network": "Understand inbound probing across your server’s ports.",
    "/attack-map":
      "Explore the countries and networks behind detected attack sources.",
    "/ports": "See which services are listening on your server.",
    "/users": "Inspect local accounts and their login shell capabilities.",
    "/activity": "Every signal, in one persistent timeline.",
  };
  useEffect(() => {
    setMenu(false);
    setSelected(null);
    document.title = `VPSentry · ${page}`;
  }, [location.pathname, page]);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <aside className={`sidebar ${menu ? "open" : ""}`}>
        <Link className="brand" to="/">
          <span className="brand-symbol">
            <Shield size={25} strokeWidth={1.8} />
            <span />
          </span>
          vpsentry<span className="brand-period">.</span>
        </Link>
        <div className="workspace">
          <span className="workspace-icon">
            <Server size={18} />
          </span>
          <div>
            <strong>My server</strong>
            <small>Self-hosted workspace</small>
          </div>
          <LockKeyhole size={13} />
        </div>
        <div className="nav-caption">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map(([path, label, Icon]) => (
            <NavLink key={path} to={path} end>
              <Icon size={18} />
              {label}
              {path === "/activity" && <span className="nav-live" />}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="local-note">
            <Shield size={18} />
            <strong>Your server. Your data.</strong>
            <p>
              Events stored on this machine.
              <br />
              Optional online GeoIP lookups.
            </p>
          </div>
          <div className="version">
            <span className="status-dot green" /> VPSentry{" "}
            <span>v{health.data?.version ?? "0.1.0"}</span>
          </div>
        </div>
      </aside>
      {menu && (
        <button
          className="sidebar-scrim"
          aria-label="Close navigation"
          onClick={() => setMenu(false)}
        />
      )}
      <div className="main-shell">
        {testAlert && !hasLiveAttack && (
          <section
            className="attack-alert"
            role="alert"
            aria-label="Simulated security alert"
          >
            <TriangleAlert size={24} aria-hidden="true" />
            <div className="attack-alert-content">
              <strong>SIMULATION — test attack alert</strong>
              <p>
                This is only a visual preview. No attack was detected, and no
                security data is changed. Clears after 20 seconds.
              </p>
              <div className="attack-alert-incidents">
                <span>
                  Example SSH brute force ·{" "}
                  <span className="mono">192.0.2.42</span>
                </span>
                <span>
                  Example port scan ·{" "}
                  <span className="mono">198.51.100.24</span>
                </span>
              </div>
            </div>
            <button
              className="attack-alert-link"
              onClick={() => setTestAlert(false)}
            >
              End simulation <X size={16} />
            </button>
          </section>
        )}
        {!!health.data?.active_alerts?.total && (
          <section
            className="attack-alert"
            role="alert"
            aria-label="Security attack alert"
          >
            <TriangleAlert size={24} aria-hidden="true" />
            <div className="attack-alert-content">
              <strong>
                {health.error
                  ? "Security alert — connection lost"
                  : "Security alert — attack activity detected"}
              </strong>
              <p>
                {health.error
                  ? "Unable to refresh attack status. Last known incidents are shown below."
                  : "Brute-force or port-scan activity observed within the last 2 minutes."}
              </p>
              <div className="attack-alert-incidents">
                {health.data.active_alerts.items.map((event) => (
                  <button key={event.id} onClick={() => setSelected(event)}>
                    {title(event.type)} ·{" "}
                    <span className="mono">
                      {event.source_ip || "Unknown source"}
                    </span>
                    <ChevronRight size={14} />
                  </button>
                ))}
              </div>
            </div>
            <Link to="/activity" className="attack-alert-link">
              View activity
              {health.data.active_alerts.total > 3
                ? ` (${health.data.active_alerts.total} incidents)`
                : ""}
              <ArrowUpRight size={16} />
            </Link>
          </section>
        )}
        <header className="topbar">
          <div>
            <button
              className="icon-button mobile-menu"
              aria-label="Toggle navigation"
              aria-expanded={menu}
              onClick={() => setMenu(!menu)}
            >
              <Menu size={20} />
            </button>
            <span className="muted">Workspace</span>
            <ChevronRight size={13} />
            <span>{page}</span>
          </div>
          <div>
            <span className={`connection ${health.error ? "amber" : "green"}`}>
              <span className="status-dot" />
              {health.error
                ? "Connection lost"
                : health.data
                  ? "System online"
                  : "Connecting"}
            </span>
            <span className="top-divider" />
            <span className="admin-avatar">A</span>
            <span className="admin-label">Administrator</span>
          </div>
        </header>
        <main id="main">
          <div className="page-heading">
            <div>
              <h1>{names[location.pathname] ?? "Page not found"}</h1>
              <p>
                {subtitles[location.pathname] ??
                  "Choose a page from the sidebar."}
              </p>
            </div>
            <div className="refresh-group">
              <span className="muted small">Refreshes every 5s</span>
              <button
                className="subtle-button test-alert-button"
                disabled={hasLiveAttack}
                onClick={() => setTestAlert((value) => !value)}
                title={
                  hasLiveAttack
                    ? "A real attack alert is already active"
                    : "Preview the alert banner without changing security data"
                }
              >
                <TriangleAlert size={14} />
                {testAlert ? "End test" : "Test alert"}
              </button>
              <button
                className="subtle-button"
                onClick={refreshAll}
                disabled={stats.loading}
              >
                <RefreshCw size={14} className={stats.loading ? "spin" : ""} />
                Refresh
              </button>
            </div>
          </div>
          {health.error && (
            <ErrorBox message={health.error} onRetry={health.refresh} />
          )}{" "}
          {stats.error && (
            <ErrorBox message={stats.error} onRetry={stats.refresh} />
          )}{" "}
          {location.pathname === "/attack-map" ? (
            <AttackMap />
          ) : location.pathname === "/" ? (
            <Overview
              health={health.data}
              stats={stats.data}
              onSelect={setSelected}
            />
          ) : location.pathname === "/ssh" ||
            location.pathname === "/network" ? (
            <MonitorPage
              kind={location.pathname === "/ssh" ? "ssh" : "network"}
              health={health.data}
              onSelect={setSelected}
            />
          ) : location.pathname === "/ports" ? (
            <PortsPage health={health.data} />
          ) : location.pathname === "/users" ? (
            <UsersPage />
          ) : location.pathname === "/activity" ? (
            <ActivityPage onSelect={setSelected} />
          ) : (
            <Link to="/">Back to overview</Link>
          )}
          <footer>
            <span>
              <Shield size={13} /> Read-only monitoring. You stay in control.
            </span>
            <span>
              {stats.data
                ? `Last sample ${time(stats.data.timestamp)}`
                : "Waiting for server telemetry"}
            </span>
          </footer>
        </main>
      </div>
      {selected && <EventDetails event={selected} onClose={closeDetails} />}
    </div>
  );
}
