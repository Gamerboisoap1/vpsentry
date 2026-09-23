import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Globe, MapPin, Search, ArrowUpRight, X, Info } from "lucide-react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import atlas from "world-atlas/countries-110m.json";
import { useApi, time, title } from "./api";

type Location = {
  status: string;
  message?: string;
  country?: string;
  country_code?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
};
type Source = {
  source_ip: string;
  incidents: number;
  last_seen: number;
  types: string[];
  location: Location;
};
type MapData = {
  total: number;
  enabled: boolean;
  provider: string;
  items: Source[];
};
const projection = geoNaturalEarth1().fitExtent(
  [
    [16, 16],
    [944, 450],
  ],
  { type: "Sphere" },
);
const draw = geoPath(projection);
const land = feature(
  atlas as unknown as Topology,
  atlas.objects.countries as unknown as GeometryCollection,
);
const countryPaths = land.features.map((country) => ({
  id: country.id,
  path: draw(country) || "",
}));
const statusText = (location: Location) =>
  location.status === "located"
    ? location.country || "Unknown country"
    : {
        private: "Non-public IP",
        disabled: "Lookup disabled",
        pending: "Lookup pending",
        rate_limited: "Lookup paused",
        unavailable: "Lookup unavailable",
        not_requested: "No recent attack",
      }[location.status] || "Unknown";

export function GeoIPLookup({ ip }: { ip: string }) {
  const geo = useApi<Location>("/geoip?ip=" + encodeURIComponent(ip), 30000);
  return (
    <div className="geoip-detail">
      <h4>
        <Globe size={14} /> Country / GeoIP lookup
      </h4>
      {geo.error ? (
        <p>Location unavailable. Monitoring is unaffected.</p>
      ) : !geo.data ? (
        <p>Loading location…</p>
      ) : (
        <>
          <strong>{statusText(geo.data)}</strong>
          {geo.data.status === "located" ? (
            <>
              <p>{[geo.data.city, geo.data.isp].filter(Boolean).join(" · ")}</p>
              <small>
                Approximate network location, not the person’s location.
              </small>
            </>
          ) : (
            <p>{geo.data.message}</p>
          )}
        </>
      )}
    </div>
  );
}

export default function AttackMap({ compact = false }: { compact?: boolean }) {
  const { data, error, refresh } = useApi<MapData>("/attack-map", 10000);
  const [query, setQuery] = useState("");
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const items = data?.items || [];
  const visible = useMemo(
    () =>
      items.filter((source) =>
        `${source.source_ip} ${source.location.country || ""} ${source.location.city || ""}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [items, query],
  );
  const located = visible.filter(
    (source) =>
      source.location.status === "located" &&
      typeof source.location.longitude === "number" &&
      typeof source.location.latitude === "number",
  );
  const countryCount = new Set(
    items
      .filter((s) => s.location.status === "located")
      .map((s) => s.location.country_code),
  ).size;
  const selected = items.find((s) => s.source_ip === selectedIP);
  return (
    <section
      className={`panel attack-map-panel ${compact ? "compact-map" : ""}`}
    >
      <div className="panel-heading">
        <h2>
          <Globe size={17} />
          Attack origins
        </h2>
        {compact ? (
          <Link className="text-link" to="/attack-map">
            Open attack map <ArrowUpRight size={14} />
          </Link>
        ) : (
          <span className="badge">Last 24 hours</span>
        )}
      </div>
      <div className="map-summary">
        <span>
          <strong>{data?.total ?? "—"}</strong> source IPs
        </span>
        <span>
          <strong>{data ? countryCount : "—"}</strong> located countries
        </span>
        <span>
          <strong>
            {data
              ? items.filter((s) => s.location.status !== "located").length
              : "—"}
          </strong>{" "}
          unlocated in view
        </span>
      </div>
      {error && (
        <div className="notice error" role="alert">
          <Info size={17} />
          <div>
            <strong>Couldn’t refresh attack locations</strong>
            <p>Previously received locations may be stale.</p>
          </div>
          <button onClick={refresh}>Retry</button>
        </div>
      )}
      {data && !data.enabled && (
        <div className="map-notice">
          Online GeoIP is disabled. Attack monitoring continues without external
          lookups.
        </div>
      )}
      <div className="attack-map-layout">
        <div className="world-map-wrap">
          <svg
            className="world-map"
            viewBox="0 0 960 480"
            aria-label="Approximate locations of detected attack source IPs"
            role="group"
          >
            <title>Attack origin map — last 24 hours</title>
            <path d={draw({ type: "Sphere" }) || ""} className="map-ocean" />
            <g aria-hidden="true">
              {countryPaths.map((country) => (
                <path key={country.id} d={country.path} className="map-land" />
              ))}
            </g>
            {located.map((source) => {
              const point = projection([
                source.location.longitude!,
                source.location.latitude!,
              ]);
              if (!point) return null;
              return (
                <g
                  key={source.source_ip}
                  className={`map-marker ${selectedIP === source.source_ip ? "selected" : ""}`}
                  transform={`translate(${point[0]}, ${point[1]})`}
                  tabIndex={0}
                  role="button"
                  aria-label={`${source.source_ip}, ${source.location.country}, ${source.incidents} incidents`}
                  onClick={() => setSelectedIP(source.source_ip)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      setSelectedIP(source.source_ip);
                    }
                  }}
                >
                  <title>
                    {source.source_ip} · {source.location.country} ·{" "}
                    {source.incidents} incidents
                  </title>
                  <circle r="13" className="map-marker-target" />
                  <circle r="8" className="map-marker-ring" />
                  <circle r="4" className="map-marker-dot" />
                </g>
              );
            })}
          </svg>
          <div className="map-legend">
            <span>
              <i />
              Observed source location
            </span>
            <span>Country boundaries: Natural Earth</span>
          </div>
          {!located.length && (
            <p className="map-empty">
              {!data
                ? "Loading attack locations…"
                : !items.length
                  ? "No attacks recorded in the last 24 hours. Detected sources will appear here."
                  : query
                    ? "No located sources match your filter."
                    : "No coordinates available yet. Lookup status is shown for each source below."}
            </p>
          )}
        </div>
        {!compact && (
          <aside className="map-inspector" aria-label="Selected attack source">
            {selected ? (
              <>
                <div className="map-inspector-heading">
                  <MapPin size={18} />
                  <h3>{statusText(selected.location)}</h3>
                  <button
                    className="icon-button"
                    aria-label="Clear selected source"
                    onClick={() => setSelectedIP(null)}
                  >
                    <X size={16} />
                  </button>
                </div>
                <p className="mono">{selected.source_ip}</p>
                <dl>
                  <dt>City / region estimate</dt>
                  <dd>{selected.location.city || "Unavailable"}</dd>
                  <dt>Network provider</dt>
                  <dd>{selected.location.isp || "Unavailable"}</dd>
                  <dt>Detected incidents</dt>
                  <dd>{selected.incidents}</dd>
                  <dt>Activity</dt>
                  <dd>{selected.types.map(title).join(", ")}</dd>
                  <dt>Last observed</dt>
                  <dd>
                    {new Date(selected.last_seen * 1000).toLocaleString()}
                  </dd>
                </dl>
              </>
            ) : (
              <>
                <MapPin size={25} />
                <h3>Explore an attack source</h3>
                <p>
                  Select a point on the map or a source below to see its
                  country, network and activity.
                </p>
              </>
            )}
          </aside>
        )}
      </div>
      {!compact && (
        <>
          <div className="table-toolbar">
            <label className="search-field">
              <Search size={16} />
              <input
                aria-label="Filter attack IP or country"
                placeholder="Filter by IP, country or city…"
                value={query}
                maxLength={128}
                onChange={(e) => setQuery(e.target.value)}
              />
              {query && (
                <button
                  className="icon-button"
                  aria-label="Clear location filter"
                  onClick={() => setQuery("")}
                >
                  <X size={14} />
                </button>
              )}
            </label>
            <span className="muted small">
              Showing {visible.length} of {data?.total ?? 0} sources · latest
              100 maximum
            </span>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Source IP / lookup</th>
                  <th>Country</th>
                  <th>Activity</th>
                  <th>Incidents</th>
                  <th>Last observed</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((source) => (
                  <tr
                    key={source.source_ip}
                    className={
                      selectedIP === source.source_ip ? "selected-source" : ""
                    }
                  >
                    <td>
                      <button
                        className="event-title mono"
                        onClick={() => setSelectedIP(source.source_ip)}
                      >
                        {source.source_ip}
                        <ArrowUpRight size={13} />
                      </button>
                    </td>
                    <td>
                      <span
                        className={`badge ${source.location.status === "located" ? "blue" : "neutral"}`}
                      >
                        {statusText(source.location)}
                      </span>
                    </td>
                    <td>{source.types.map(title).join(" · ")}</td>
                    <td>{source.incidents}</td>
                    <td className="mono muted">{time(source.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data && !visible.length && (
            <div className="quiet-empty">
              {items.length
                ? "No matching sources."
                : "No attack sources recorded yet."}
            </div>
          )}
        </>
      )}
      <div className="map-footnote">
        <Info size={14} />
        <p>
          GeoIP is approximate. VPNs, proxies and hosting providers can obscure
          the real origin. Public attack-source IPs are sent to{" "}
          <a
            href="https://ipwhois.io/documentation"
            target="_blank"
            rel="noreferrer"
          >
            ipwho.is
          </a>{" "}
          for cached lookups; no browser map tiles are requested.
        </p>
      </div>
    </section>
  );
}
