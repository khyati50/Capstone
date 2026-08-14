/**
 * Real-Time Socket.IO WebSockets Server Manager
 */

let io = null;

function initSocket(serverInstance) {
  const { Server } = require('socket.io');
  io = new Server(serverInstance, {
    cors: {
      origin: process.env.FRONTEND_ORIGIN || 'http://localhost:5173',
      methods: ['GET', 'POST']
    }
  });

  io.on('connection', (socket) => {
    console.log(`[Socket.IO] New Dashboard Analyst Connected: ${socket.id}`);
    try {
      const { getTelemetry } = require('./dbService');
      socket.emit('telemetry_update', getTelemetry());
    } catch (e) {
      // safe fallback
    }

    socket.on('disconnect', () => {
      console.log(`[Socket.IO] Analyst Disconnected: ${socket.id}`);
    });
  });

  return io;
}

function broadcastAlert(alertData) {
  if (io) {
    io.emit('new_alert', alertData);
  }
}

function broadcastRiskUpdate(riskData) {
  if (io) {
    io.emit('risk_update', riskData);
  }
}

function broadcastTimelineUpdate(timelineData) {
  if (io) {
    io.emit('timeline_update', timelineData);
  }
}

function broadcastMitreUpdate(mitreData) {
  if (io) {
    io.emit('mitre_update', mitreData);
  }
}

function broadcastTelemetry(telemetryData) {
  if (io) {
    io.emit('telemetry_update', telemetryData);
  }
}

function broadcastResetState() {
  if (io) {
    io.emit('reset_state');
  }
}

module.exports = {
  initSocket,
  broadcastAlert,
  broadcastRiskUpdate,
  broadcastTimelineUpdate,
  broadcastMitreUpdate,
  broadcastTelemetry,
  broadcastResetState
};
