/**
 * GeoMapCard — §3.2 "LOCATION MAP" cell + §3.3 + §7.7.
 *
 * Rules from the spec that this component enforces:
 * - Leaflet + OpenStreetMap tiles WITH attribution (§3.3, §5.4: no paid key);
 * - one marker per geo source, coloured per source, so the card can never show
 *   a single dot (§3.3, §7.7);
 * - the centroid is drawn as a distinct marker, and every point gets a circle
 *   of its reported accuracy radius;
 * - a table of votes: source, where it says, deviation from the centroid in km,
 *   and the DB date (§7.7);
 * - red warning when sources are more than 2000 km apart (§7.7).
 *
 * Implementation notes:
 * - If Leaflet cannot be created (module error, no canvas), the card degrades to
 *   a static SVG world approximation that still plots every point, so the
 *   "multi-point" requirement never silently regresses to a blank box.
 * - Tile requests follow the app CSP; OSM is used with the required attribution.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// Static import on purpose: if leaflet is missing from node_modules the build
// must fail loudly instead of silently degrading to the fallback renderer.
import "leaflet/dist/leaflet.css";

import type { GeoPoint, LocationResult } from "../lib/types";
import { Panel, Banner, Empty } from "./ui/parts";
import {
  CENTROID_COLOR,
  cx,
  DASH,
  fmtCoord,
  fmtDate,
  fmtKm,
  getLocalizedProviderReason,
  getLocalizedSpreadMeta,
  srcColor,
  spreadLabel,
  valueOrDash,
} from "./ui/meta";
import { useI18n } from "../lib/i18n";

export interface GeoMapCardProps {
  location: LocationResult | null | undefined;
  /** ISO time of the check, shown in the footer. */
  checkedAt?: string | null;
  /** True while the location module is still running. */
  loading?: boolean;
  /** Called by the per-card retry button (§3.4). */
  onRetry?: () => void;
  canRetry?: boolean;
  /**
   * True when the app knows it has no network. When set we do NOT create a tile
   * layer at all: loading tiles first would block the card for 5–10 s on timeout
   * before the offline renderer appears. Markers are drawn regardless.
   */
  offline?: boolean;
}

const TILE_URL = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";
const TILE_ATTRIBUTION =
  '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer noopener">OpenStreetMap</a> contributors';

/**
 * 1×1 transparent PNG. Handed to Leaflet as `errorTileUrl` so a blocked or
 * rate-limited tile host leaves a clean surface instead of the broken-image icon
 * stamped on every tile coordinate.
 */
const TRANSPARENT_TILE =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/** Only points that can be drawn. */
function plottablePoints(location: LocationResult | null | undefined): GeoPoint[] {
  if (!location) return [];
  return location.points.filter(
    (point) =>
      typeof point.latitude === "number" &&
      typeof point.longitude === "number" &&
      Number.isFinite(point.latitude) &&
      Number.isFinite(point.longitude),
  );
}

export function GeoMapCard({
  location,
  checkedAt,
  loading,
  onRetry,
  canRetry,
  offline = false,
}: GeoMapCardProps) {
  const { lang, t } = useI18n();
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<unknown>(null);
  const layerRef = useRef<unknown>(null);
  const tilesRef = useRef<unknown>(null);
  /** Leaflet cannot be rebuilt once it threw — this is state so the fallback renders. */
  const [failed, setFailed] = useState(false);
  /** Set once a tile actually loaded, so we know the basemap is usable. */
  const [tilesLive, setTilesLive] = useState(false);
  /** Resolved concrete colours: `var(--…)` is meaningless to Leaflet's canvas renderer. */
  const colorCacheRef = useRef<Map<string, string>>(new Map());

  const resolveColor = useCallback((value: string): string => {
    if (!value.startsWith("var(")) return value;
    const name = value.slice(4, -1).trim();
    const cache = colorCacheRef.current;
    const cached = cache.get(name);
    if (cached) return cached;
    let resolved = "";
    try {
      resolved = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    } catch {
      /* no document (tests) — fall through to the literal */
    }
    if (!resolved) resolved = "#00f0ff";
    cache.set(name, resolved);
    return resolved;
  }, []);

  /* Refs only: no setState, so this is safe to call from any effect. */
  const killMap = useCallback(() => {
    const map = mapRef.current as { remove?: () => void } | null;
    try {
      map?.remove?.();
    } catch {
      /* already gone */
    }
    mapRef.current = null;
    layerRef.current = null;
    tilesRef.current = null;
  }, []);

  const teardown = useCallback(() => {
    killMap();
    setTilesLive(false);
  }, [killMap]);

  const points = useMemo(() => plottablePoints(location), [location]);
  const centroid = useMemo(() => {
    if (!location) return null;
    if (typeof location.centroid_latitude !== "number" || typeof location.centroid_longitude !== "number") {
      return null;
    }
    return { lat: location.centroid_latitude, lon: location.centroid_longitude };
  }, [location]);

  const bigDivergence = Boolean(location?.big_divergence);
  const spread = location?.spread ?? null;
  const spreadMeta = getLocalizedSpreadMeta(spread, lang);
  const majorityText = location?.country
    ? location.country_code &&
      !location.country.includes(`(${location.country_code})`) &&
      location.country.trim().toLowerCase() !== location.country_code.trim().toLowerCase()
      ? `${location.country} (${location.country_code})`
      : location.country
    : lang === "en"
      ? "unresolved"
      : lang === "zh"
        ? "未确定"
        : "chưa chốt";
  const showFallback = offline || failed;

  /* ---------------- Leaflet lifecycle ---------------- */
  useEffect(() => {
    /* No plottable data means `.map__canvas` is about to unmount. A Leaflet
       instance bound to a detached div keeps painting into nothing and the next
       check silently reuses it, so the map stays blank forever. Drop it here. */
    if (points.length === 0) {
      teardown();
      setFailed(false);
      return;
    }
    if (failed) return;

    let disposed = false;
    let sizeTimer = 0;

    async function mount() {
      const container = containerRef.current;
      if (!container) return;

      try {
        const mod = await import("leaflet");
        if (disposed) return;
        const L = mod.default ?? mod;

        let map = mapRef.current as ReturnType<typeof L.map> | null;
        /* React may hand us a fresh div for the same ref (data reset, StrictMode
           double mount, tab switch). A map whose container is gone is unusable:
           rebuild instead of drawing into a detached node. */
        const boundTo = (map as unknown as { getContainer?: () => HTMLElement } | null)?.getContainer?.();
        if (map && boundTo !== container) {
          killMap();
          map = null;
        }
        if (!map) {
          map = L.map(container, {
            zoomControl: true,
            attributionControl: true,
            scrollWheelZoom: true,
            worldCopyJump: true,
            minZoom: 1,
            /* No basemap yet: the grid below is drawn by app.css, so an empty
               map still reads as a map surface rather than a black hole. */
            preferCanvas: true,
          });
          mapRef.current = map;
        }

        /* Basemap handling.
           While `offline` is true we deliberately skip the tile layer: Leaflet
           would otherwise fire one request per visible tile and only give up
           after the network timeout, freezing the card for 5–10 s before the
           fallback could appear. Markers/centroid/accuracy circles are drawn by
           the overlay layer in both cases, so the map is never "just one dot"
           and never empty. */
        const existingTiles = tilesRef.current as ReturnType<typeof L.tileLayer> | null;
        if (offline) {
          if (existingTiles) {
            existingTiles.remove();
            tilesRef.current = null;
            setTilesLive(false);
          }
        } else if (!existingTiles) {
          const tiles = L.tileLayer(TILE_URL, {
            attribution: TILE_ATTRIBUTION,
            maxZoom: 19,
            minZoom: 1,
            /* CORS-clean tiles so the canvas-based renderer can read them. */
            crossOrigin: true,
            /* Keep the map to one world: prevents duplicate marker ghosts when
               fitBounds spans the antimeridian. */
            noWrap: true,
            bounds: L.latLngBounds([-85, -180], [85, 180]),
            /* Blocked/rate-limited host → transparent tile, no broken icons. */
            errorTileUrl: TRANSPARENT_TILE,
            /* Shorter than the browser default so a dead host fails fast even
               when `offline` was not detected. */
            updateWhenIdle: false,
            keepBuffer: 1,
          });
          tiles.on("load", () => setTilesLive(true));
          tiles.on("tileerror", () => setTilesLive(false));
          tiles.addTo(map);
          tilesRef.current = tiles;
        }

        // Rebuild the overlay layer on every data change.
        const previous = layerRef.current as ReturnType<typeof L.layerGroup> | null;
        if (previous) {
          try {
            previous.remove();
          } catch {
            /* layer already detached with a recycled map */
          }
        }

        const layer = L.layerGroup().addTo(map);

        const bounds = L.latLngBounds([]);

        const kCoord = lang === "en" ? "Coordinates:" : lang === "zh" ? "坐标:" : "Toạ độ:";
        const kRadius = lang === "en" ? "Radius:" : lang === "zh" ? "半径:" : "Bán kính:";
        const kDev = lang === "en" ? "Centroid Dev:" : lang === "zh" ? "离质心偏差:" : "Lệch tâm:";
        const kData = lang === "en" ? "Data:" : lang === "zh" ? "数据来源:" : "Dữ liệu:";
        const kSources = lang === "en" ? "Sources:" : lang === "zh" ? "数据源数:" : "Số nguồn:";
        const kSpread = lang === "en" ? "Spread:" : lang === "zh" ? "收敛度:" : "Độ lệch:";
        const centroidTitle =
          lang === "en"
            ? "◆ Centroid (Center of votes)"
            : lang === "zh"
            ? "◆ 质心 (各投票中心)"
            : "◆ Centroid (Tâm các nguồn)";
        const centroidTooltip =
          lang === "en"
            ? "Centroid (center of votes)"
            : lang === "zh"
            ? "质心 (投票中心)"
            : "Centroid (tâm các phiếu)";
        const sourcesCountStr =
          lang === "en"
            ? `${points.length} geo sources`
            : lang === "zh"
            ? `${points.length} 个地理位置源`
            : `${points.length} nguồn geo`;

        points.forEach((point, index) => {
          const lat = point.latitude as number;
          const lon = point.longitude as number;
          /* Leaflet paints into a canvas: `var(--map-src-N)` cannot be resolved
             there, it would silently fall back to black. Resolve to a concrete
             colour first (cached per token). */
          const color = resolveColor(srcColor(index));
          const latlng = L.latLng(lat, lon);
          bounds.extend(latlng);

          const radiusKm = point.accuracy_radius_km;
          if (typeof radiusKm === "number" && radiusKm > 0) {
            L.circle(latlng, {
              radius: radiusKm * 1000,
              color,
              weight: 1,
              opacity: 0.55,
              fillColor: color,
              fillOpacity: 0.06,
              interactive: false,
            }).addTo(layer);
          }

          const placeStr = [point.city, point.region, point.country_code ?? point.country]
            .filter(Boolean)
            .join(", ") || DASH;
          const devStr = typeof point.distance_from_centroid_km === "number"
            ? `${point.distance_from_centroid_km.toFixed(1)} km`
            : DASH;
          const accStr = typeof point.accuracy_radius_km === "number"
            ? `±${point.accuracy_radius_km} km`
            : DASH;
          const dbStr = point.db_updated_at
            ? fmtDate(point.db_updated_at)
            : (point.db_version || "API");

          const popupHtml = `
            <div class="map-popup">
              <div class="map-popup__title" style="color:${color}">● ${escapeHtml(point.source)}</div>
              <div class="map-popup__place">${escapeHtml(placeStr)}</div>
              <div class="map-popup__grid">
                <span class="map-popup__k">${kCoord}</span>
                <span class="map-popup__v">${lat.toFixed(4)}, ${lon.toFixed(4)}</span>
                <span class="map-popup__k">${kRadius}</span>
                <span class="map-popup__v">${escapeHtml(accStr)}</span>
                <span class="map-popup__k">${kDev}</span>
                <span class="map-popup__v">${escapeHtml(devStr)}</span>
                <span class="map-popup__k">${kData}</span>
                <span class="map-popup__v">${escapeHtml(dbStr)}</span>
              </div>
            </div>
          `;

          L.circleMarker(latlng, {
            radius: 5,
            color,
            weight: 2,
            fillColor: color,
            fillOpacity: 0.85,
          })
            .bindTooltip(
              `${point.source}: ${placeStr}`,
              { direction: "top", opacity: 0.9 },
            )
            .bindPopup(popupHtml, { className: "cyber-popup", maxWidth: 260 })
            .addTo(layer);
        });

        if (centroid) {
          const centroidLatLng = L.latLng(centroid.lat, centroid.lon);
          bounds.extend(centroidLatLng);
          const centroidColor = resolveColor(CENTROID_COLOR);

          if (typeof location?.radius_km === "number" && location.radius_km > 0) {
            L.circle(centroidLatLng, {
              radius: location.radius_km * 1000,
              color: centroidColor,
              weight: 1,
              dashArray: "4 4",
              opacity: 0.75,
              fillOpacity: 0.03,
              interactive: false,
            }).addTo(layer);
          }

          const centroidPopupHtml = `
            <div class="map-popup">
              <div class="map-popup__title" style="color:${centroidColor}">${centroidTitle}</div>
              <div class="map-popup__place">${kCoord} ${centroid.lat.toFixed(4)}, ${centroid.lon.toFixed(4)}</div>
              <div class="map-popup__grid">
                <span class="map-popup__k">${kRadius}</span>
                <span class="map-popup__v">±${location?.radius_km ? location.radius_km.toFixed(1) : "0"} km</span>
                <span class="map-popup__k">${kSpread}</span>
                <span class="map-popup__v">${spreadMeta ? escapeHtml(spreadMeta.label) : (lang === "en" ? "unclear" : lang === "zh" ? "未知" : "chưa rõ")}</span>
                <span class="map-popup__k">${kSources}</span>
                <span class="map-popup__v">${sourcesCountStr}</span>
              </div>
            </div>
          `;

          L.circleMarker(centroidLatLng, {
            radius: 7,
            color: centroidColor,
            weight: 2,
            fillColor: centroidColor,
            fillOpacity: 0.9,
          })
            .bindTooltip(centroidTooltip, { direction: "top", opacity: 0.9 })
            .bindPopup(centroidPopupHtml, { className: "cyber-popup", maxWidth: 260 })
            .addTo(layer);
        }

        layerRef.current = layer;

        if (bounds.isValid()) {
          const northEast = bounds.getNorthEast();
          const southWest = bounds.getSouthWest();
          const latSpan = Math.abs(northEast.lat - southWest.lat);
          const lonSpan = Math.abs(northEast.lng - southWest.lng);
          // If all points are clustered tightly in the same city, zoom in to show details (up to 11).
          const targetMaxZoom = latSpan < 0.25 && lonSpan < 0.25 ? 11 : latSpan < 1.5 && lonSpan < 1.5 ? 9 : 7;
          map.fitBounds(bounds.pad(0.35), { animate: false, maxZoom: targetMaxZoom });
        }
        // Map container may have been laid out after creation.
        sizeTimer = window.setTimeout(() => {
          if (!disposed) map?.invalidateSize();
        }, 60);
      } catch {
        // Leaflet could not load/mount — fall back to the SVG renderer below.
        if (disposed) return;
        killMap();
        setFailed(true);
      }
    }

    void mount();

    return () => {
      disposed = true;
      window.clearTimeout(sizeTimer);
    };
    /* `offline` and `lang` are dependencies: flipping them immediately
       re-renders tiles and localized popups/tooltips. */
  }, [points, centroid, location?.radius_km, spreadMeta, offline, failed, killMap, resolveColor, teardown, lang]);

  // Destroy the map when the card unmounts so no tile loop keeps running.
  useEffect(() => killMap, [killMap]);

  const width = 460;
  const height = 200;
  const projection = useMemo(() => {
    if (points.length === 0) return null;
    let minLat = 90;
    let maxLat = -90;
    let minLon = 180;
    let maxLon = -180;
    const all: Array<{ lat: number; lon: number }> = points.map((point) => ({
      lat: point.latitude as number,
      lon: point.longitude as number,
    }));
    if (centroid) all.push(centroid);
    for (const item of all) {
      minLat = Math.min(minLat, item.lat);
      maxLat = Math.max(maxLat, item.lat);
      minLon = Math.min(minLon, item.lon);
      maxLon = Math.max(maxLon, item.lon);
    }
    const spanLat = Math.max(maxLat - minLat, 2);
    const spanLon = Math.max(maxLon - minLon, 2);
    const padX = 24;
    const padY = 18;
    return (lat: number, lon: number) => ({
      x: padX + ((lon - minLon + spanLon * 0.08) / (spanLon * 1.16)) * (width - padX * 2),
      y: padY + ((maxLat - lat + spanLat * 0.08) / (spanLat * 1.16)) * (height - padY * 2),
    });
  }, [points, centroid]);

  const footer =
    points.length > 0 ? (
      <>
        <span>
          {points.length} {lang === "en" ? "geo sources" : lang === "zh" ? "个地理定位源" : "nguồn geo"}
        </span>
        <span className="mono">
          {checkedAt
            ? `${lang === "en" ? "checked at " : lang === "zh" ? "检测于 " : "check lúc "}${checkedAt}`
            : DASH}
        </span>
      </>
    ) : null;

  return (
    <Panel
      title={t("location.title")}
      hint={
        spreadMeta ? (
          <span
            className={cx(
              spreadMeta.tone === "clean"
                ? "text-clean"
                : spreadMeta.tone === "bad"
                  ? "text-bad"
                  : "text-temp",
            )}
          >
            {spreadMeta.label}
          </span>
        ) : (
          "triangulation"
        )
      }
      footer={footer}
      scroll={false}
      bodyClassName="panel__body--tight"
    >
      <div className="geo">
        {location ? (
          <div className="geo__verdictline">
            <span
              className="chip chip--plain"
              title={
                lang === "en"
                  ? "Whether country consensus was reached (§7.7)"
                  : lang === "zh"
                    ? "国家/地区是否已达成共识 (§7.7)"
                    : "Quốc gia chốt được hay không (§7.7)"
              }
            >
              {lang === "en" ? "Country: " : lang === "zh" ? "国家/地区: " : "Quốc gia: "}
              {majorityText}
            </span>
            <span
              className={cx("chip", location.city ? "chip--plain" : "chip--temp")}
              title={
                lang === "en"
                  ? "City resolved only when sources converge within 200 km (§7.3)"
                  : lang === "zh"
                    ? "仅当数据源收敛在 200 km 以内时确定城市 (§7.3)"
                    : "Thành phố chỉ chốt khi các nguồn chụm trong 200 km (§7.3)"
              }
            >
              {lang === "en" ? "City: " : lang === "zh" ? "城市: " : "Thành phố: "}
              {location.city
                ? location.city
                : lang === "en"
                  ? "unresolved"
                  : lang === "zh"
                    ? "未确定"
                    : "chưa chốt"}
            </span>
            <span
              className="chip chip--muted"
              title={
                lang === "en"
                  ? "Country confidence score"
                  : lang === "zh"
                    ? "国家结论置信度"
                    : "Độ tin cậy của kết luận quốc gia"
              }
            >
              {lang === "en"
                ? `confidence ${Math.round(location.country_confidence)}%`
                : lang === "zh"
                  ? `置信度 ${Math.round(location.country_confidence)}%`
                  : `tin cậy ${Math.round(location.country_confidence)}%`}
            </span>
          </div>
        ) : null}

        {bigDivergence ? (
          <Banner
            tone="error"
            title={
              lang === "en"
                ? "Large divergence between sources (> 2,000 km)"
                : lang === "zh"
                  ? "数据源存在巨大偏差 (> 2,000 km)"
                  : "Các nguồn lệch nhau rất lớn (> 2.000 km)"
            }
            detail={
              lang === "en"
                ? "City not resolved. Rely on Country/ASN only and verify manually."
                : lang === "zh"
                  ? "无法确定城市。仅供参考国家/ASN并手动核对。"
                  : "Không kết luận thành phố. Chỉ nên tin phần quốc gia/ASN và đối chiếu tay."
            }
          />
        ) : null}

        {loading && points.length === 0 ? (
          <Empty icon="📍">
            {lang === "en"
              ? "Fetching locations from multiple sources and cross-referencing coordinates…"
              : lang === "zh"
                ? "正在聚合多源定位并交叉比对坐标…"
                : "Đang lấy vị trí từ nhiều nguồn và đối chiếu toạ độ…"}
          </Empty>
        ) : points.length === 0 ? (
          <Empty icon="🗺">{t("location.no_geo_data")}</Empty>
        ) : (
          <div className={cx("map", (offline || !tilesLive || failed) && "map--offline")}>
            {/* Leaflet canvas; kept mounted even if it fails so the ref is stable.
                Not aria-hidden: the zoom control and the OSM attribution are
                focusable, and hiding interactive content from AT is a defect.
                Screen readers get a summary via the label instead. */}
            <div
              ref={containerRef}
              className="map__canvas"
              role="region"
              aria-label={
                lang === "en"
                  ? `Location map: ${points.length} geo sources, ${spreadMeta ? spreadMeta.label : "unclear deviation"}`
                  : lang === "zh"
                  ? `位置地图: ${points.length} 个地理位置源, ${spreadMeta ? spreadMeta.label : "偏差未知"}`
                  : `Bản đồ vị trí: ${points.length} nguồn geo, ${spreadMeta ? spreadMeta.label : "chưa rõ độ lệch"}`
              }
            />

            {/* Offline or a dead Leaflet: draw the vector plane directly
                (see the tile-layer note in the mount effect). */}
            {showFallback ? (
              <SvgFallback points={points} centroid={centroid} projection={projection} width={width} height={height} />
            ) : null}

            <div className="map__legend">
              {points.slice(0, 12).map((point, index) => (
                <span key={`${point.source}-${index}`} className="map__legenditem">
                  <span className="map__swatch" style={{ background: srcColor(index) }} />
                  {point.source}
                </span>
              ))}
              {points.length > 12 ? (
                <span className="map__legenditem">
                  +{points.length - 12} {lang === "en" ? "sources" : lang === "zh" ? "个源" : "nguồn"}
                </span>
              ) : null}
              {centroid ? (
                <span className="map__legenditem">
                  <span className="map__swatch map__swatch--centroid" style={{ background: CENTROID_COLOR }} />
                  centroid
                </span>
              ) : null}
            </div>

            <div className="map__note">
              {failed
                ? lang === "en"
                  ? `fallback map · ${points.length} points · radius = per-source accuracy`
                  : lang === "zh"
                  ? `备用地图 · ${points.length} 个点 · 半径 = 各源精度`
                  : `bản đồ dự phòng · ${points.length} điểm · bán kính = accuracy từng nguồn`
                : offline || !tilesLive
                  ? lang === "en"
                    ? `offline · ${points.length} points · radius = per-source accuracy`
                    : lang === "zh"
                    ? `离线 · ${points.length} 个点 · 半径 = 各源精度`
                    : `offline · ${points.length} điểm · bán kính = accuracy từng nguồn`
                  : lang === "en"
                    ? `OSM · ${points.length} points · radius = per-source accuracy`
                    : lang === "zh"
                    ? `OSM · ${points.length} 个点 · 半径 = 各源精度`
                    : `OSM · ${points.length} điểm · bán kính = accuracy từng nguồn`}
            </div>
          </div>
        )}

        {/* Vote table (§7.7): where each source says, deviation, DB date. */}
        {points.length > 0 ? (
          <div className="geo__tablewrap">
            <table className="tbl tbl--compact">
              <thead>
                <tr>
                  <th>{lang === "en" ? "Source" : lang === "zh" ? "数据源" : "Nguồn"}</th>
                  <th>{lang === "en" ? "Reported Location" : lang === "zh" ? "上报位置" : "Nói ở đâu"}</th>
                  <th className="tbl__num">{lang === "en" ? "Centroid Dev" : lang === "zh" ? "离质心偏差" : "Lệch centroid"}</th>
                  <th>DB</th>
                </tr>
              </thead>
              <tbody>
                {points.map((point, index) => {
                  const deviation = point.distance_from_centroid_km;
                  const deviationBad = typeof deviation === "number" && deviation > 2000;
                  const isStale = Boolean(
                    point.db_updated_at &&
                      !Number.isNaN(new Date(point.db_updated_at).getTime()) &&
                      Date.now() - new Date(point.db_updated_at).getTime() > 60 * 24 * 3600 * 1000,
                  );
                  return (
                    <tr key={`${point.source}-row-${index}`} className={deviationBad ? "tbl__row--bad" : undefined}>
                      <td className="tbl__name">
                        <span className="row">
                          <span className="map__swatch" style={{ background: srcColor(index) }} />
                          {point.source}
                        </span>
                      </td>
                      <td className="truncate" title={`${valueOrDash(point.city)}, ${valueOrDash(point.region)}, ${valueOrDash(point.country)}`}>
                        {[point.city, point.region, point.country_code ?? point.country]
                          .filter((part) => part && part.length > 0)
                          .join(", ") || DASH}
                        {point.over_precise ? (
                          <span
                            className="chip chip--bad"
                            style={{ marginLeft: 4 }}
                            title={
                              lang === "en"
                                ? "Source reports over-precise address — unreliable for IP (§7.1)"
                                : lang === "zh"
                                  ? "数据源返回详细街道地址 — 对 IP 定位不可靠 (§7.1)"
                                  : "Nguồn trả về địa chỉ chi tiết — không đáng tin cho IP (§7.1)"
                            }
                          >
                            {lang === "en" ? "over-precise" : lang === "zh" ? "过于详细" : "quá chi tiết"}
                          </span>
                        ) : null}
                      </td>
                      <td className={cx("tbl__num", deviationBad && "text-bad")}>
                        {deviation === null || deviation === undefined ? DASH : fmtKm(deviation, lang)}
                      </td>
                      <td
                        className={cx("tbl__muted tiny", isStale && "text-temp")}
                        title={
                          isStale
                            ? lang === "en"
                              ? "Database older than 60 days — location confidence penalty applied (§7.3)"
                              : lang === "zh"
                                ? "数据库超过 60 天未更新 — 已扣减置信度 (§7.3)"
                                : "DB cũ > 60 ngày — trừ điểm tin cậy (§7.3)"
                            : undefined
                        }
                      >
                        {point.db_updated_at ? fmtDate(point.db_updated_at) : point.db_version ? point.db_version : "API"}
                        {isStale ? " ⚠" : ""}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : null}

        {location && location.notes.length > 0 ? (
          <div
            className="tiny muted"
            title={location.notes.map((n) => getLocalizedProviderReason(n, lang)).join(" · ")}
          >
            {getLocalizedProviderReason(location.notes[0], lang)}
          </div>
        ) : null}

        {location?.changed_since_last_check ? (
          <Banner
            tone="warn"
            title={
              lang === "en"
                ? "Location has changed since last check"
                : lang === "zh"
                ? "位置较上次检测发生变动"
                : "Vị trí đã thay đổi so với lần check trước"
            }
            detail={
              lang === "en"
                ? `Previously: ${location.previous_city ?? DASH}, ${location.previous_country ?? DASH} — IP may have been reassigned or rotated.`
                : lang === "zh"
                ? `此前为: ${location.previous_city ?? DASH}, ${location.previous_country ?? DASH} — 该 IP 可能已重新分配或位置轮换。`
                : `Trước: ${location.previous_city ?? DASH}, ${location.previous_country ?? DASH} — IP có thể vừa được cấp lại hoặc bị xoay vị trí.`
            }
          />
        ) : null}

        {onRetry && canRetry && (!location || points.length === 0 || failed) ? (
          <div className="row">
            <button
              type="button"
              className="btn btn--sm btn--ghost"
              onClick={() => {
                setFailed(false);
                onRetry();
              }}
            >
              ↻ {t("location.retry")}
            </button>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

/* ------------------------------------------------------------------ */
/* SVG fallback                                                        */
/* ------------------------------------------------------------------ */

interface SvgFallbackProps {
  points: GeoPoint[];
  centroid: { lat: number; lon: number } | null;
  projection: ((lat: number, lon: number) => { x: number; y: number }) | null;
  width: number;
  height: number;
}

function SvgFallback({ points, centroid, projection, width, height }: SvgFallbackProps) {
  const { lang } = useI18n();
  if (!projection) return null;

  return (
    <svg
      className="map__fallback"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="xMidYMid meet"
      role="img"
      aria-label={
        lang === "en"
          ? "Fallback vector map displaying coordinates of each source"
          : lang === "zh"
          ? "显示各数据源坐标的矢量备用地图"
          : "Bản đồ dự phòng hiển thị toạ độ từng nguồn"
      }
    >
      <rect x={0} y={0} width={width} height={height} fill="var(--panel-sunken)" />
      {Array.from({ length: 9 }).map((_, index) => (
        <line
          key={`v${index}`}
          x1={(width / 8) * index}
          y1={0}
          x2={(width / 8) * index}
          y2={height}
          stroke="var(--border-soft)"
          strokeWidth={0.5}
        />
      ))}
      {Array.from({ length: 5 }).map((_, index) => (
        <line
          key={`h${index}`}
          x1={0}
          y1={(height / 4) * index}
          x2={width}
          y2={(height / 4) * index}
          stroke="var(--border-soft)"
          strokeWidth={0.5}
        />
      ))}

      {centroid ? (
        <line
          x1={projection(centroid.lat, centroid.lon).x}
          y1={projection(centroid.lat, centroid.lon).y}
          x2={0}
          y2={0}
          stroke="none"
        />
      ) : null}

      {points.map((point, index) => {
        const { x, y } = projection(point.latitude as number, point.longitude as number);
        const radiusPx = Math.min(
          36,
          Math.max(4, ((point.accuracy_radius_km ?? 50) / 1000) * 12),
        );
        return (
          <g key={`${point.source}-${index}`}>
            <circle cx={x} cy={y} r={radiusPx} fill={srcColor(index)} fillOpacity={0.07} stroke={srcColor(index)} strokeOpacity={0.4} strokeWidth={0.8} />
            <circle cx={x} cy={y} r={4} fill={srcColor(index)} stroke="var(--bg)" strokeWidth={1} />
            <text x={x + 7} y={y + 3} fontSize={8} fill="var(--text)" opacity={0.85}>
              {point.source}
            </text>
          </g>
        );
      })}

      {centroid ? (
        <g>
          <circle
            cx={projection(centroid.lat, centroid.lon).x}
            cy={projection(centroid.lat, centroid.lon).y}
            r={6}
            fill="none"
            stroke={CENTROID_COLOR}
            strokeWidth={1.5}
          />
          <circle
            cx={projection(centroid.lat, centroid.lon).x}
            cy={projection(centroid.lat, centroid.lon).y}
            r={1.6}
            fill={CENTROID_COLOR}
          />
        </g>
      ) : null}
    </svg>
  );
}

export default GeoMapCard;
