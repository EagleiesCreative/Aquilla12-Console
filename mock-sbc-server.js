const http = require("http");
const { WebSocketServer } = require("ws");

const PORT = 8085;

// Initialize 12 channel states
const channels = Array.from({ length: 12 }).map((_, index) => {
  const id = index + 1;
  return {
    id,
    status: "IDLE",
    duration: 0,
    audioLevel: 0,
    latency: 0,
    jitter: 0,
    packetLoss: 0,
    rxKbps: 0,
    txKbps: 0,
    targetUri: "",
    codec: "Opus"
  };
});

// Helper to broadcast WebSocket messages to all connected clients
const clients = new Set();
function broadcast(payload) {
  const message = JSON.stringify(payload);
  for (const client of clients) {
    if (client.readyState === 1) { // OPEN
      client.send(message);
    }
  }
}

// Log formatting helper
function getTimestamp() {
  return new Date().toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

// REST HTTP Server handling CORS + Call commands
const server = http.createServer((req, res) => {
  // CORS Headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // POST /api/channels/:id/call
  if (req.method === "POST" && req.url.match(/\/api\/channels\/\d+\/call/)) {
    const channelId = parseInt(req.url.split("/")[3]);
    let body = "";
    req.on("data", chunk => body += chunk);
    req.on("end", () => {
      try {
        const data = JSON.parse(body || "{}");
        const channel = channels.find(c => c.id === channelId);
        
        if (!channel) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Channel not found" }));
          return;
        }

        channel.targetUri = data.targetUri || "sip:default";
        channel.codec = data.codec || "Opus";
        channel.status = "RINGING";
        channel.duration = 0;

        console.log(`[SBC Engine] [CH ${channelId}] Outbound call initiated to: ${channel.targetUri}`);
        
        // 1. Notify dialing/ringing state
        broadcast({
          type: "channel_update",
          data: {
            id: channelId,
            status: "RINGING",
            duration: 0,
            targetUri: channel.targetUri,
            codec: channel.codec
          }
        });

        broadcast({
          type: "log",
          data: {
            level: "sip_tx",
            channelId: channelId,
            message: `[SBC Link] Outbound INVITE sent to ${channel.targetUri}`
          }
        });

        // 2. Simulate ringing -> connected delay
        setTimeout(() => {
          if (channel.status === "RINGING") {
            channel.status = "CONNECTED";
            channel.latency = 22;
            channel.jitter = 2;
            channel.packetLoss = 0.0;
            channel.rxKbps = channel.codec === "Opus" ? 64 : 80;
            channel.txKbps = channel.codec === "Opus" ? 64 : 80;

            console.log(`[SBC Engine] [CH ${channelId}] Call connected with ${channel.codec}`);

            broadcast({
              type: "channel_update",
              data: {
                id: channelId,
                status: "CONNECTED",
                latency: channel.latency,
                jitter: channel.jitter,
                packetLoss: channel.packetLoss,
                rxKbps: channel.rxKbps,
                txKbps: channel.txKbps
              }
            });

            broadcast({
              type: "log",
              data: {
                level: "sip_rx",
                channelId: channelId,
                message: `[SBC Link] SIP/2.0 200 OK. Audio session negotiated on mapping ${channel.codec}`
              }
            });

            broadcast({
              type: "log",
              data: {
                level: "success",
                channelId: channelId,
                message: `[SBC Link] RTP stream active: Hardware I2S capture linked to network stream.`
              }
            });
          }
        }, 1500);

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true }));
      } catch (e) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON" }));
      }
    });
    return;
  }

  // POST /api/channels/:id/hangup
  if (req.method === "POST" && req.url.match(/\/api\/channels\/\d+\/hangup/)) {
    const channelId = parseInt(req.url.split("/")[3]);
    const channel = channels.find(c => c.id === channelId);

    if (!channel) {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Channel not found" }));
      return;
    }

    const wasConnected = channel.status === "CONNECTED";
    channel.status = "IDLE";
    channel.audioLevel = 0;
    channel.duration = 0;

    console.log(`[SBC Engine] [CH ${channelId}] Call terminated by request.`);

    broadcast({
      type: "channel_update",
      data: {
        id: channelId,
        status: "IDLE",
        audioLevel: 0,
        duration: 0,
        latency: 0,
        jitter: 0,
        packetLoss: 0,
        rxKbps: 0,
        txKbps: 0
      }
    });

    broadcast({
      type: "log",
      data: {
        level: "sip_tx",
        channelId: channelId,
        message: wasConnected ? "[SBC Link] SIP BYE sent to target." : "[SBC Link] CANCEL sent to target."
      }
    });

    broadcast({
      type: "log",
      data: {
        level: "info",
        channelId: channelId,
        message: `[SBC Link] Channel mapping released. Slot ${channelId - 1} unlinked.`
      }
    });

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // Catch-all 404
  res.writeHead(404);
  res.end("Not Found");
});

// Create WebSocket server attached to the HTTP server
const wss = new WebSocketServer({ server });

wss.on("connection", (ws) => {
  console.log("[SBC WS] Dashboard client connected to telemetry events stream");
  clients.add(ws);

  // Send initial state on connection
  channels.forEach((ch) => {
    ws.send(JSON.stringify({
      type: "channel_update",
      data: ch
    }));
  });

  ws.send(JSON.stringify({
    type: "log",
    data: {
      level: "success",
      message: "[SBC WS] Hardware channel telemetry synced with connected dashboard client"
    }
  }));

  ws.on("close", () => {
    console.log("[SBC WS] Dashboard client disconnected");
    clients.delete(ws);
  });
});

// Periodic simulated tasks:
// 1. Audio VU levels (every 100ms) for active/connected streams
setInterval(() => {
  channels.forEach((ch) => {
    if (ch.status === "CONNECTED") {
      // Human speech volume fluctuation simulation
      const rand = Math.random();
      if (rand > 0.85) {
        ch.audioLevel = Math.max(0, ch.audioLevel - 20); // Pause
      } else if (rand > 0.75) {
        ch.audioLevel = Math.floor(Math.random() * 15) + 83; // Peak
      } else {
        const delta = Math.floor(Math.random() * 30) - 15;
        ch.audioLevel = Math.max(20, Math.min(80, ch.audioLevel + delta));
      }
      
      broadcast({
        type: "audio_level",
        data: { id: ch.id, level: ch.audioLevel }
      });
    }
  });
}, 100);

// 2. Hardware Resource Statistics (every 1s) and Call Duration increment
setInterval(() => {
  const activeCount = channels.filter(c => c.status === "CONNECTED").length;
  
  // Base stats plus call loading
  const cpu = Math.min(99, Math.round(15 + activeCount * 4.5 + (Math.random() * 4 - 2)));
  const ram = Math.min(95, Math.round(38 + activeCount * 0.8 + (Math.random() * 2 - 1)));

  broadcast({
    type: "telemetry",
    data: { cpu, ram }
  });

  channels.forEach((ch) => {
    if (ch.status === "CONNECTED") {
      ch.duration += 1;
      
      // Update duration and slightly fluctuate network telemetry
      ch.latency = Math.max(10, Math.min(120, ch.latency + (Math.random() > 0.7 ? (Math.random() > 0.5 ? 1 : -1) : 0)));
      ch.jitter = Math.max(1, Math.min(20, ch.jitter + (Math.random() > 0.8 ? (Math.random() > 0.5 ? 1 : -1) : 0)));
      ch.packetLoss = Math.max(0, Math.min(10, ch.packetLoss + (Math.random() > 0.95 ? 0.15 : Math.random() > 0.95 ? -0.15 : 0)));

      broadcast({
        type: "channel_update",
        data: {
          id: ch.id,
          duration: ch.duration,
          latency: ch.latency,
          jitter: ch.jitter,
          packetLoss: ch.packetLoss
        }
      });
    }
  });
}, 1000);

// Launch Mock server
server.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 MOCK SBC BACKEND SERVER RUNNING ON PORT ${PORT}`);
  console.log(`👉 REST API endpoints: http://localhost:${PORT}/api/channels/:id/[call|hangup]`);
  console.log(`👉 WebSocket stream:    ws://localhost:${PORT}/events`);
  console.log(`======================================================\n`);
});
