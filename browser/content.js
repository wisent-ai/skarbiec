// Content script: finds login forms, offers Skarbiec fill on a badge next to
// each password field, and writes the chosen credentials into the form.
// All styling arrives as strings so the badge inherits nothing from the page.

const BADGE_ATTR = "data-skarbiec-badge";
const HOOKED_ATTR = "data-skarbiec-hooked";

function usernameCandidates(root) {
  const selectors = [
    'input[autocomplete="username"]',
    'input[autocomplete="email"]',
    'input[type="email"]',
    'input[name*="user" i]',
    'input[name*="email" i]',
    'input[id*="user" i]',
    'input[id*="email" i]',
    'input[type="text"]',
    'input[type="tel"]',
  ];
  for (const selector of selectors) {
    const field = root.querySelector(selector);
    if (field && !field.disabled && !field.readOnly) {
      return field;
    }
  }
  return null;
}

function totpCandidate(root) {
  const selectors = [
    'input[autocomplete="one-time-code"]',
    'input[name*="otp" i]',
    'input[name*="totp" i]',
    'input[id*="otp" i]',
    'input[id*="totp" i]',
  ];
  for (const selector of selectors) {
    const field = root.querySelector(selector);
    if (field) {
      return field;
    }
  }
  return null;
}

function setFieldValue(field, value) {
  if (!field || !value) {
    return;
  }
  field.focus();
  field.value = value;
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
}

function formRootFor(passwordField) {
  return passwordField.closest("form") || document.body;
}

function fillInto(passwordField, credentials) {
  const root = formRootFor(passwordField);
  setFieldValue(usernameCandidates(root), credentials.username);
  setFieldValue(passwordField, credentials.password);
  if (credentials.totp) {
    setFieldValue(totpCandidate(root), credentials.totp);
  }
}

function requestFill(loginId, passwordField) {
  chrome.runtime.sendMessage({ type: "skarbiec-fill", id: loginId }, (reply) => {
    if (reply && reply.ok) {
      fillInto(passwordField, reply);
    }
  });
}

function chooseAndFill(logins, passwordField) {
  if (logins.length === Number("1")) {
    requestFill(logins[Number("0")].id, passwordField);
    return;
  }
  const menu = document.createElement("div");
  menu.setAttribute(BADGE_ATTR, "menu");
  Object.assign(menu.style, {
    position: "absolute",
    zIndex: "2147483647",
    background: "#1c1c1e",
    color: "#f2f2f7",
    borderRadius: "8px",
    padding: "6px",
    boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
    fontFamily: "-apple-system, sans-serif",
    fontSize: "13px",
  });
  for (const login of logins) {
    const row = document.createElement("button");
    row.type = "button";
    row.textContent = `${login.name} — ${login.username}`;
    Object.assign(row.style, {
      display: "block",
      width: "100%",
      textAlign: "left",
      background: "none",
      border: "none",
      color: "inherit",
      padding: "6px 10px",
      cursor: "pointer",
      borderRadius: "6px",
    });
    row.addEventListener("click", () => {
      menu.remove();
      requestFill(login.id, passwordField);
    });
    menu.appendChild(row);
  }
  const rect = passwordField.getBoundingClientRect();
  menu.style.top = `${rect.bottom + window.scrollY}px`;
  menu.style.left = `${rect.left + window.scrollX}px`;
  document.body.appendChild(menu);
  const close = (event) => {
    if (!menu.contains(event.target)) {
      menu.remove();
      document.removeEventListener("click", close);
    }
  };
  document.addEventListener("click", close);
}

function offerFill(passwordField) {
  chrome.runtime.sendMessage(
    { type: "skarbiec-list", domain: location.hostname },
    (reply) => {
      if (reply && reply.ok && reply.logins && reply.logins.length > Number("0")) {
        chooseAndFill(reply.logins, passwordField);
      }
    },
  );
}

function attachBadge(passwordField) {
  if (passwordField.hasAttribute(HOOKED_ATTR) || !passwordField.isConnected) {
    return;
  }
  passwordField.setAttribute(HOOKED_ATTR, "true");
  const badge = document.createElement("button");
  badge.type = "button";
  badge.textContent = "S";
  badge.title = "Fill from Skarbiec";
  Object.assign(badge.style, {
    position: "absolute",
    zIndex: "2147483647",
    width: "22px",
    height: "22px",
    borderRadius: "50%",
    border: "none",
    background: "#0a84ff",
    color: "#ffffff",
    fontFamily: "-apple-system, sans-serif",
    fontSize: "12px",
    fontWeight: "700",
    cursor: "pointer",
    padding: "0",
    lineHeight: "22px",
    textAlign: "center",
  });
  const place = () => {
    const rect = passwordField.getBoundingClientRect();
    badge.style.top = `${rect.top + window.scrollY + (rect.height - badge.offsetHeight) / Number("2")}px`;
    badge.style.left = `${rect.right + window.scrollX - badge.offsetWidth - Number("6")}px`;
  };
  badge.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    offerFill(passwordField);
  });
  document.body.appendChild(badge);
  place();
  window.addEventListener("scroll", place, { passive: true });
  window.addEventListener("resize", place);
}

function scan() {
  for (const field of document.querySelectorAll('input[type="password"]')) {
    attachBadge(field);
  }
}

scan();
new MutationObserver(scan).observe(document.documentElement, {
  childList: true,
  subtree: true,
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.type === "skarbiec-fill-credentials") {
    const field = document.querySelector('input[type="password"]');
    if (field) {
      fillInto(field, message.credentials);
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: "no password field on this page" });
    }
  }
  return undefined;
});
