import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import "./styles/tokens.css";
import "./styles/global.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("Root element #root is missing from index.html");
}

/**
 * Record the host platform on `<html>` so CSS can compensate for the macOS
 * overlay title bar, which floats the traffic lights over the webview instead of
 * reserving a strip for them. Windows and Linux get no inset.
 *
 * Set before React mounts so the first paint is already correct — doing it in an
 * effect would visibly shift the whole layout on launch.
 */
const platform = /Mac/i.test(navigator.userAgent)
  ? "macos"
  : /Win/i.test(navigator.userAgent)
    ? "windows"
    : "linux";
document.documentElement.dataset.platform = platform;

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);