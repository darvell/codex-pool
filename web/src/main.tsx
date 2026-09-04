import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Self-hosted so the app's own Content-Security-Policy (style-src/font-src
// 'self') can serve them. Loading these from Google Fonts is blocked in
// production and silently falls back to system faces. Only the weights the
// stylesheet actually uses are imported.
import "@fontsource/cormorant-garamond/500.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "@fontsource/ibm-plex-mono/600.css";
import "@fontsource/ibm-plex-sans-condensed/400.css";
import "@fontsource/ibm-plex-sans-condensed/500.css";
import "./styles.css";
import { App } from "./App";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
