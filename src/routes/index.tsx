import { createFileRoute } from "@tanstack/react-router";
// Single-file frontend: the whole app (all subpages) lives in public/index.html
import html from "../../public/index.html?raw";

export const Route = createFileRoute("/")({
  server: {
    handlers: {
      GET: () =>
        new Response(html, {
          headers: { "content-type": "text/html; charset=utf-8" },
        }),
    },
  },
});
