// Toolbar popup: lists vault logins matching the active tab host and sends
// the chosen one to the tab's content script. DOM is built in code with
// string styles so nothing here depends on external assets.

const root = document.createElement("main");
Object.assign(root.style, {
  minWidth: "260px",
  maxWidth: "340px",
  fontFamily: "-apple-system, sans-serif",
  fontSize: "13px",
  color: "#1c1c1e",
  padding: "8px",
});
document.body.appendChild(root);

function showStatus(text) {
  root.textContent = "";
  const line = document.createElement("p");
  line.textContent = text;
  Object.assign(line.style, { color: "#6e6e73", margin: "8px" });
  root.appendChild(line);
}

function loginRow(tab, login) {
  const row = document.createElement("button");
  row.type = "button";
  Object.assign(row.style, {
    display: "block",
    width: "100%",
    textAlign: "left",
    background: "none",
    border: "none",
    padding: "8px 10px",
    cursor: "pointer",
    borderRadius: "8px",
  });
  const name = document.createElement("strong");
  name.textContent = login.name;
  const user = document.createElement("div");
  user.textContent = login.username;
  Object.assign(user.style, { color: "#6e6e73", fontSize: "12px" });
  row.appendChild(name);
  row.appendChild(user);
  row.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "skarbiec-fill", id: login.id }, (reply) => {
      if (!reply || !reply.ok) {
        showStatus(reply && reply.error ? reply.error : "Could not read the login");
        return;
      }
      chrome.tabs.sendMessage(
        tab.id,
        { type: "skarbiec-fill-credentials", credentials: reply },
        () => window.close(),
      );
    });
  });
  return row;
}

async function activeTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[Number("0")];
}

async function main() {
  const tab = await activeTab();
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    showStatus("Open a web page to fill a login.");
    return;
  }
  const host = new URL(tab.url).hostname;
  chrome.runtime.sendMessage({ type: "skarbiec-list", domain: host }, (reply) => {
    if (!reply || !reply.ok) {
      const detail = reply && reply.error ? reply.error : "vault unreachable";
      showStatus(`Skarbiec unavailable: ${detail}`);
      return;
    }
    if (!reply.logins || reply.logins.length === Number("0")) {
      showStatus(`No logins in the vault for ${host}.`);
      return;
    }
    root.textContent = "";
    for (const login of reply.logins) {
      root.appendChild(loginRow(tab, login));
    }
  });
}

main();
