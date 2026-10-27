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
        (answer) => {
          // The page's content script answers whether it filled; a page
          // without it, or without a password field, is said, not closed on.
          if (chrome.runtime.lastError) {
            showStatus(`The page could not be reached: ${chrome.runtime.lastError.message}`);
            return;
          }
          if (!answer) {
            showStatus("This page did not answer the fill; reload it and try again.");
            return;
          }
          if (!answer.ok) {
            showStatus(`The page refused the fill: ${answer.error}`);
            return;
          }
          // A fill without its one-time code stays open to say why; a
          // complete fill closes the popup.
          if (reply.totp_unavailable) {
            showStatus(`Filled without a one-time code: ${reply.totp_unavailable}`);
            return;
          }
          window.close();
        },
      );
    });
  });
  // A code page the fill cannot find a field on still needs the code: Copy
  // code reads it and puts it on the clipboard, or says why there is none.
  const code = document.createElement("button");
  code.type = "button";
  code.textContent = "Copy code";
  Object.assign(code.style, { fontSize: "11px", margin: "0 10px 6px" });
  code.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "skarbiec-fill", id: login.id }, (reply) => {
      if (!reply || !reply.ok) {
        showStatus(reply && reply.error ? reply.error : "Could not read the login");
        return;
      }
      if (!reply.totp) {
        showStatus(reply.totp_unavailable
          ? `${login.name} gives no one-time code: ${reply.totp_unavailable}`
          : `${login.name} gives no one-time code and Skarbiec said no reason; run skarbiec totp ${login.id}.`);
        return;
      }
      navigator.clipboard.writeText(reply.totp).then(
        () => showStatus(`Copied the one-time code of ${login.name}; it stays on the clipboard until something else is copied.`),
        (error) => showStatus(`The browser refused the clipboard: ${error}`),
      );
    });
  });
  // The username is already in the list, so copying it asks the vault nothing.
  const copyUser = document.createElement("button");
  copyUser.type = "button";
  copyUser.textContent = "Copy username";
  Object.assign(copyUser.style, { fontSize: "11px", margin: "0 0 6px 10px" });
  copyUser.addEventListener("click", () => {
    navigator.clipboard.writeText(login.username).then(
      () => showStatus(`Copied the username of ${login.name}.`),
      (error) => showStatus(`The browser refused the clipboard: ${error}`),
    );
  });
  const entry = document.createElement("div");
  entry.appendChild(row);
  entry.appendChild(copyUser);
  entry.appendChild(code);
  return entry;
}

async function activeTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
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
    // Logins added since autofill was connected answer nothing until its
    // grant covers them; say so instead of letting them look absent.
    const uncovered = Array.isArray(reply.unreadable) ? reply.unreadable : [];
    const coverHint = uncovered.length
      ? `${uncovered.map((row) => row.id).join(", ")} cannot be offered yet: run skarbiec browser cover, or Cover them under Settings → Policy → Browser autofill in Skarbiec.`
      : "";
    if (!reply.logins.length) {
      showStatus(`No logins in the vault for ${host}.${coverHint ? ` ${coverHint}` : ""}`);
      searchEverywhere(tab);
      offerForm(host);
      return;
    }
    root.textContent = "";
    const list = document.createElement("div");
    const show = (text) => {
      list.textContent = "";
      const needle = text.trim().toLowerCase();
      const shown = reply.logins.filter((login) =>
        `${login.name} ${login.username}`.toLowerCase().includes(needle));
      for (const login of shown) {
        list.appendChild(loginRow(tab, login));
      }
      if (!shown.length) {
        const none = document.createElement("p");
        none.textContent = `No login for ${host} has "${text.trim()}" in its name or username.`;
        Object.assign(none.style, { color: "#6e6e73", margin: "8px" });
        list.appendChild(none);
      }
    };
    // Several logins for one site: a box narrows them by name or username.
    const [, ...more] = reply.logins;
    if (more.length) {
      const filter = document.createElement("input");
      filter.type = "search";
      filter.placeholder = "Filter by name or username";
      Object.assign(filter.style, { width: "100%", boxSizing: "border-box", padding: "6px 8px", marginBottom: "4px" });
      filter.addEventListener("input", () => show(filter.value));
      root.appendChild(filter);
      filter.focus();
    }
    root.appendChild(list);
    show("");
    if (coverHint) {
      const note = document.createElement("p");
      note.textContent = coverHint;
      Object.assign(note.style, { color: "#6e6e73", fontSize: "12px", margin: "8px" });
      root.appendChild(note);
    }
    // Where this site takes a new password: the well-known address a site
    // answers with its own change-password page (W3C Well-Known URL for
    // Changing Passwords), as `skarbiec sites` names it.
    const change = document.createElement("a");
    change.href = `https://${host}/.well-known/change-password`;
    change.textContent = `Change a password on ${host}`;
    change.target = "_blank";
    change.rel = "noopener";
    Object.assign(change.style, { display: "block", fontSize: "12px", margin: "8px" });
    root.appendChild(change);
    offerForm(host);
  });
}

// Why an offer was not kept, from the host's answer: its error, the inbox's
// admission status, or that no answer came at all.
function offerRefusal(reply) {
  if (!reply) {
    return "no answer from the native host";
  }
  if (reply.error) {
    return reply.error;
  }
  return `the vault's inbox refused it (${reply.status}): a login under ${reply.id} is already the owner's or another writer's`;
}

// Just signed up? The new login goes to the vault's donation inbox, sealed
// to the owner's key, and waits there until the owner accepts it in
// Skarbiec's Requests inbox, or with `skarbiec donation accept`. The
// extension keeps nothing of it once it is sent.
function offerForm(host) {
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = `Save a new login for ${host}`;
  Object.assign(summary.style, { fontSize: "12px", margin: "8px", cursor: "pointer" });
  details.appendChild(summary);
  const field = (placeholder, type) => {
    const input = document.createElement("input");
    input.type = type;
    input.placeholder = placeholder;
    Object.assign(input.style, { width: "100%", boxSizing: "border-box", padding: "6px 8px", marginBottom: "4px" });
    details.appendChild(input);
    return input;
  };
  const username = field("Username or email", "text");
  const password = field("Password", "password");
  const send = document.createElement("button");
  send.type = "button";
  send.textContent = "Send to Skarbiec for approval";
  const said = document.createElement("p");
  Object.assign(said.style, { color: "#6e6e73", fontSize: "12px", margin: "8px" });
  send.addEventListener("click", () => {
    if (!username.value.trim() || !password.value) {
      said.textContent = "Both the username and the password are needed.";
      return;
    }
    chrome.runtime.sendMessage(
      { type: "skarbiec-offer", site: host, username: username.value.trim(), password: password.value },
      (reply) => {
        password.value = "";
        if (!reply || !reply.ok) {
          said.textContent = `Not saved: ${offerRefusal(reply)}`;
          return;
        }
        said.textContent = `Sent as ${reply.id}; accept it in Skarbiec to keep it.`;
      },
    );
  });
  details.appendChild(send);
  details.appendChild(said);
  root.appendChild(details);
}

// A login kept under another address of the same service — a regional
// domain, a renamed one — is not offered on this host; a search over every
// login's name, username and sites finds it, and fills it as any other.
function searchEverywhere(tab) {
  const box = document.createElement("input");
  box.type = "search";
  box.placeholder = "Search every login, then press Return";
  Object.assign(box.style, { width: "100%", boxSizing: "border-box", padding: "6px 8px" });
  const found = document.createElement("div");
  box.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || !box.value.trim()) {
      return;
    }
    chrome.runtime.sendMessage({ type: "skarbiec-search", text: box.value.trim() }, (reply) => {
      found.textContent = "";
      if (!reply || !reply.ok) {
        const why = document.createElement("p");
        why.textContent = `Skarbiec could not search: ${reply && reply.error ? reply.error : "no answer from the native host"}`;
        found.appendChild(why);
        return;
      }
      if (!reply.logins.length) {
        const none = document.createElement("p");
        none.textContent = `No login's name, username or site holds "${box.value.trim()}".`;
        Object.assign(none.style, { color: "#6e6e73", margin: "8px" });
        found.appendChild(none);
        return;
      }
      for (const login of reply.logins) {
        found.appendChild(loginRow(tab, login));
      }
    });
  });
  root.appendChild(box);
  root.appendChild(found);
  box.focus();
}

main();
