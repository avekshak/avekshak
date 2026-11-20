import dgram from "node:dgram";
import net from "node:net";
import { normalizeSyslog } from "../../normalize/syslog.js";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";

export interface SyslogListener {
  close(): Promise<void>;
}

interface SyslogOptions {
  udpPort?: number;
  tcpPort?: number;
  host?: string;
  queue: TypedQueue<NormalizedEvent>;
  onSkip?: (line: string) => void;
}

export async function handleSyslogLine(
  line: string,
  queue: TypedQueue<NormalizedEvent>,
  onSkip?: (line: string) => void,
): Promise<boolean> {
  const ev = normalizeSyslog(line);
  if (ev === null) {
    onSkip?.(line);
    return false;
  }
  await queue.enqueue("syslog", ev);
  return true;
}

export function startSyslogListener(opts: SyslogOptions): Promise<SyslogListener> {
  const udpPort = opts.udpPort ?? 5514;
  const tcpPort = opts.tcpPort ?? 5514;
  const host = opts.host ?? "0.0.0.0";
  const { queue, onSkip } = opts;

  const udp = dgram.createSocket("udp4");
  udp.on("message", (msg) => {
    void handleSyslogLine(msg.toString("utf8"), queue, onSkip);
  });
  udp.on("error", (err) => {
    console.error("[syslog/udp] error:", err.message);
  });

  const tcp = net.createServer((socket) => {
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      let idx: number;
      while ((idx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        void handleSyslogLine(line, queue, onSkip);
      }
    });
    socket.on("end", () => {
      if (buffer.trim().length > 0) {
        void handleSyslogLine(buffer, queue, onSkip);
      }
    });
    socket.on("error", (err) => {
      console.error("[syslog/tcp] socket error:", err.message);
    });
  });

  return new Promise<SyslogListener>((resolve, reject) => {
    let pending = 2;
    const fail = (err: Error) => reject(err);
    const ready = () => {
      pending -= 1;
      if (pending === 0) {
        console.log(
          `[syslog] listening udp/${udpPort} tcp/${tcpPort} on ${host}`,
        );
        resolve({
          close: async () => {
            await new Promise<void>((r) => udp.close(() => r()));
            await new Promise<void>((r) => tcp.close(() => r()));
          },
        });
      }
    };
    udp.once("error", fail);
    tcp.once("error", fail);
    udp.bind(udpPort, host, ready);
    tcp.listen(tcpPort, host, ready);
  });
}
