import { createServer as createTcpServer, type Socket } from "net";
import { createSocket } from "dgram";
import { createQueue } from "@avekshak/queue";
import { normalizeSyslog } from "../normalize/syslog.js";
import type { NormalizedEvent } from "@avekshak/schema";

const SYSLOG_UDP_PORT = Number(process.env.SYSLOG_UDP_PORT ?? 514);
const SYSLOG_TCP_PORT = Number(process.env.SYSLOG_TCP_PORT ?? 601);

const queue = createQueue<NormalizedEvent>("ingest");

function handleLine(line: string): void {
  const event = normalizeSyslog(line);
  if (!event) {
    console.warn("[syslog] dropped malformed line:", line.slice(0, 80));
    return;
  }
  queue.enqueue("syslog", event).catch((err) => {
    console.error("[syslog] enqueue error:", err);
  });
}

// UDP receiver
export function startSyslogUdp(): void {
  const sock = createSocket("udp4");
  sock.on("message", (msg) => {
    for (const line of msg.toString().split("\n")) {
      if (line.trim()) handleLine(line.trim());
    }
  });
  sock.on("error", (err) => console.error("[syslog:udp] error:", err));
  sock.bind(SYSLOG_UDP_PORT, () =>
    console.log(`[syslog:udp] listening on port ${SYSLOG_UDP_PORT}`),
  );
}

// TCP receiver (newline-delimited)
export function startSyslogTcp(): void {
  const server = createTcpServer((socket: Socket) => {
    let buf = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      buf += chunk;
      const lines = buf.split("\n");
      buf = lines.pop() ?? "";
      for (const line of lines) {
        if (line.trim()) handleLine(line.trim());
      }
    });
    socket.on("error", (err) => console.error("[syslog:tcp] socket error:", err));
  });
  server.listen(SYSLOG_TCP_PORT, () =>
    console.log(`[syslog:tcp] listening on port ${SYSLOG_TCP_PORT}`),
  );
}
