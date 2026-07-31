// Background service worker: owns the native messaging port to the skarbiec
// host and relays list/fill requests from the popup and content scripts.
// The vault token never touches this process — the native host holds it.

const HOST_NAME = "ai.wisent.skarbiec";

let port = null;
// The host answers frames strictly in order, so pending promises form a
// FIFO rather than an id-keyed map.
const pending = [];

function ensurePort() {
  if (port) {
    return port;
  }
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener((frame) => {
    const next = pending.shift();
    if (next) {
      next.resolve(frame);
    }
  });
  port.onDisconnect.addListener(() => {
    const error = chrome.runtime.lastError;
    port = null;
    while (pending.length > Number("0")) {
      const next = pending.shift();
      next.resolve({
        ok: false,
        error: error ? error.message : "native host disconnected",
      });
    }
  });
  return port;
}

function callNative(message) {
  return new Promise((resolve) => {
    pending.push({ resolve });
    try {
      ensurePort().postMessage(message);
    } catch (error) {
      pending.pop();
      resolve({ ok: false, error: String(error) });
    }
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type || !message.type.startsWith("skarbiec-")) {
    return undefined;
  }
  if (message.type === "skarbiec-ping") {
    callNative({ action: "ping" }).then(sendResponse);
    return true;
  }
  if (message.type === "skarbiec-list") {
    callNative({ action: "list", domain: message.domain }).then(sendResponse);
    return true;
  }
  if (message.type === "skarbiec-fill") {
    callNative({ action: "fill", id: message.id }).then(sendResponse);
    return true;
  }
  return undefined;
});
