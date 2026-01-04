// src/api.js
import axios from "axios";

export const API_BASE = (import.meta.env.VITE_API_BASE || "http://localhost:8000").replace(/\/+$/, "");

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

export async function rebuildIncidents() {
  const { data } = await api.post("/incidents/rebuild");
  return data;
}

export async function getIncidents() {
  const { data } = await api.get("/incidents");
  return data;
}

export async function getIncident(id) {
  const { data } = await api.get(`/incidents/${id}`);
  return data;
}

export async function patchIncident(id, payload) {
  const { data } = await api.patch(`/incidents/${id}`, payload);
  return data;
}

export async function getAlerts() {
  const { data } = await api.get("/alerts");
  return data;
}

export async function getPlaybook(id) {
  const { data } = await api.get(`/incidents/${id}/playbook`);
  return data;
}

export async function simulateRemediate(id, action) {
  const { data } = await api.post(`/incidents/${id}/simulate_remediate`, { action });
  return data;
}

export async function exportIncident(id) {
  const { data } = await api.get(`/incidents/${id}/export`);
  return data;
}

/* -------------------------------------------------------
 * WebSocket helpers (Real-time alert streaming)
 * ------------------------------------------------------ */
export function getAlertsWSUrl() {
  // Convert http(s)://host -> ws(s)://host
  const base = API_BASE;
  const wsBase = base.startsWith("https://")
    ? base.replace("https://", "wss://")
    : base.replace("http://", "ws://");

  return `${wsBase}/ws/alerts`;
}

export function connectAlertsWS({
  onOpen,
  onClose,
  onError,
  onMessage,
  reconnect = true,
  reconnectDelayMs = 1200,
  maxReconnectDelayMs = 12000,
} = {}) {
  let ws = null;
  let closedByUser = false;
  let delay = reconnectDelayMs;

  const url = getAlertsWSUrl();

  const connect = () => {
    ws = new WebSocket(url);

    ws.onopen = () => {
      delay = reconnectDelayMs;
      onOpen && onOpen();
    };

    ws.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        onMessage && onMessage(data);
      } catch {
        // ignore bad payloads
      }
    };

    ws.onerror = (err) => {
      onError && onError(err);
    };

    ws.onclose = () => {
      onClose && onClose();
      if (!closedByUser && reconnect) {
        const nextDelay = Math.min(delay, maxReconnectDelayMs);
        setTimeout(() => {
          delay = Math.min(delay * 1.5, maxReconnectDelayMs);
          connect();
        }, nextDelay);
      }
    };
  };

  connect();

  return {
    close: () => {
      closedByUser = true;
      try {
        ws && ws.close();
      } catch {
        // ignore
      }
    },
    send: (text) => {
      try {
        ws && ws.readyState === WebSocket.OPEN && ws.send(text);
      } catch {
        // ignore
      }
    },
  };
}
