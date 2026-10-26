/**
 * Front-end entry point (§2.3). Mounts the single-screen app of §3.2.
 *
 * Styles are imported here, in this order, so tokens exist before any component
 * CSS is evaluated and so Leaflet's own stylesheet (imported from GeoMapCard)
 * can be overridden by app.css.
 */

import React from "react";
import ReactDOM from "react-dom/client";

import "./styles/tokens.css";
import "./styles/app.css";

import App from "./App";
import { isTauri, openExternal } from "./lib/api";
import { I18nProvider } from "./lib/i18n";

/**
 * Delegate every external link to the OS browser.
 *
 * Tauri v2 has no implicit `<a target="_blank">` handler, and Leaflet draws its
 * own OSM attribution — neither can be fixed per-component. One capture-phase
 * listener covers provider source links and the required tile attribution.
 */
if (isTauri()) {
  document.addEventListener(
    "click",
    (event) => {
      const target = event.target as Element | null;
      const anchor = target?.closest?.("a[href]") as HTMLAnchorElement | null;
      if (!anchor) return;
      const href = anchor.getAttribute("href") ?? "";
      if (!/^https?:\/\//i.test(href)) return;
      event.preventDefault();
      void openExternal(href);
    },
    true,
  );
}

const container = document.getElementById("root");

if (!container) {
  // Should never happen: index.html owns #root. Fail loudly instead of a blank window.
  throw new Error("Không tìm thấy phần tử #root trong index.html");
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <I18nProvider>
      <App />
    </I18nProvider>
  </React.StrictMode>,
);
