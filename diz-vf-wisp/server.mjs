import { createServer } from "node:http";
import { logging, server as wisp } from "@mercuryworkshop/wisp-js/server";

const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || "").split(",").map((origin) => origin.trim()).filter(Boolean),
);
const wispPath = process.env.WISP_PATH || "/wisp/";
const activeConnections = new Set();

logging.set_level(logging.WARN);
Object.assign(wisp.options, {
  allow_direct_ip: false,
  allow_loopback_ips: false,
  allow_private_ips: false,
  allow_udp_streams: false,
  hostname_blacklist: [/^metadata(?:[.-]|$)/i, /\.internal\.?$/i, /\.local\.?$/i],
  port_whitelist: [80, 443],
  stream_limit_per_host: 8,
  stream_limit_total: 32,
});

const server = createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
  response.end("diz_vf Wisp backend\n");
});

server.on("upgrade", (request, socket, head) => {
  if (request.url !== wispPath || !allowedOrigins.has(request.headers.origin)) {
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    return;
  }
  if (activeConnections.size >= 64) {
    socket.end("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    return;
  }
  activeConnections.add(socket);
  socket.once("close", () => activeConnections.delete(socket));
  wisp.routeRequest(request, socket, head);
});

server.listen(Number(process.env.PORT || 8080), "0.0.0.0");
