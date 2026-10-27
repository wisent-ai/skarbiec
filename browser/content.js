// Content script: finds login forms, offers Skarbiec fill on a badge next to
// each password field — or, on the account step of a sign-in that asks for
// the password on a later page, next to the account field — and writes the
// chosen credentials into the form. All styling arrives as strings so the
// badge inherits nothing from the page.

const BADGE_ATTR = "data-skarbiec-badge";
const HOOKED_ATTR = "data-skarbiec-hooked";
// The fields a sign-in shows alone on a page of their own: the account before
// its password page, or the one-time code after it.
const IDENTIFIER_FIELD = 'input[autocomplete="username"], input[autocomplete="email"], input[type="email"], input[autocomplete="one-time-code"]';

// The first field matching one of the selectors, in their order of trust.
function firstMatch(root, selectors, usable) {
  for (const selector of selectors) {
    const field = root.querySelector(selector);
    if (field && usable(field)) {
      return field;
    }
  }
  return null;
}

function usernameCandidates(root) {
  return firstMatch(root, [
    'input[autocomplete="username"]', 'input[autocomplete="email"]', 'input[type="email"]',
    'input[name*="user" i]', 'input[name*="email" i]', 'input[id*="user" i]', 'input[id*="email" i]',
    'input[type="text"]', 'input[type="tel"]',
  ], (field) => !field.disabled && !field.readOnly);
}

function totpCandidate(root) {
  return firstMatch(root, [
    'input[autocomplete="one-time-code"]', 'input[name*="otp" i]', 'input[name*="totp" i]',
    'input[id*="otp" i]', 'input[id*="totp" i]',
  ], () => true);
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
  // A step of its own takes only its value: the username on the account
  // page, the one-time code on the code page.
  if (passwordField.type !== "password") {
    const code = passwordField.autocomplete === "one-time-code";
    setFieldValue(passwordField, code ? credentials.totp : credentials.username);
    return;
  }
  const root = formRootFor(passwordField);
  setFieldValue(usernameCandidates(root), credentials.username);
  setFieldValue(passwordField, credentials.password);
  if (credentials.totp) {
    setFieldValue(totpCandidate(root), credentials.totp);
  }
}

// One line under the password field saying what the host answered when it
// could not fill: the badge is the only surface on the page, so a refusal
// that is not shown here is not shown at all. The note goes on the next click.
function showNote(passwordField, text) {
  const note = document.createElement("div");
  note.setAttribute(BADGE_ATTR, "note");
  note.textContent = text;
  Object.assign(note.style, {
    position: "absolute",
    zIndex: "2147483647",
    background: "#1c1c1e",
    color: "#f2f2f7",
    borderRadius: "8px",
    padding: "6px 10px",
    maxWidth: "360px",
    fontFamily: "-apple-system, sans-serif",
    fontSize: "12px",
  });
  const rect = passwordField.getBoundingClientRect();
  note.style.top = `${rect.bottom + window.scrollY}px`;
  note.style.left = `${rect.left + window.scrollX}px`;
  document.body.appendChild(note);
  const close = () => {
    note.remove();
    document.removeEventListener("click", close);
  };
  document.addEventListener("click", close);
}

function requestFill(loginId, passwordField) {
  chrome.runtime.sendMessage({ type: "skarbiec-fill", id: loginId }, (reply) => {
    if (!reply) {
      showNote(passwordField, "Skarbiec's native host gave no answer.");
      return;
    }
    if (!reply.ok) {
      showNote(passwordField, `Skarbiec could not fill: ${reply.error}`);
      return;
    }
    fillInto(passwordField, reply);
    if (reply.totp_unavailable) {
      showNote(passwordField, `Filled without a one-time code: ${reply.totp_unavailable}`);
    }
  });
}

function chooseAndFill(logins, passwordField) {
  const [only, ...others] = logins;
  if (!others.length) {
    requestFill(only.id, passwordField);
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
      if (!reply) {
        showNote(passwordField, "Skarbiec's native host gave no answer.");
        return;
      }
      if (!reply.ok) {
        showNote(passwordField, `Skarbiec unavailable: ${reply.error}`);
        return;
      }
      // A login added since autofill was connected answers nothing until its
      // grant covers it; name it rather than letting it look absent.
      const uncovered = Array.isArray(reply.unreadable) ? reply.unreadable : [];
      if (!reply.logins.length) {
        const hint = uncovered.length
          ? ` ${uncovered.map((row) => row.id).join(", ")} cannot be offered yet: run skarbiec browser cover, or Cover them in Skarbiec.`
          : "";
        showNote(passwordField, `No logins in the vault for ${location.hostname}.${hint}`);
        return;
      }
      chooseAndFill(reply.logins, passwordField);
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
    badge.style.top = `${rect.top + window.scrollY + (rect.height - badge.offsetHeight) / 2}px`;
    badge.style.left = `${rect.right + window.scrollX - badge.offsetWidth - 6}px`;
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
  const passwords = document.querySelectorAll('input[type="password"]');
  for (const field of passwords) {
    attachBadge(field);
  }
  // No password field yet: the account step of a two-step sign-in.
  if (!passwords.length) {
    for (const field of document.querySelectorAll(IDENTIFIER_FIELD)) {
      attachBadge(field);
    }
  }
}

scan();
new MutationObserver(scan).observe(document.documentElement, {
  childList: true,
  subtree: true,
});

// The sign-in field the person is in, or else the page's first password
// field, or on the account step of a two-step sign-in its account field.
function targetPasswordField() {
  const focused = document.activeElement;
  if (focused && focused.matches && focused.matches(`input[type="password"], ${IDENTIFIER_FIELD}`)) {
    return focused;
  }
  const password = document.querySelector('input[type="password"]');
  if (password) {
    return password;
  }
  return document.querySelector(IDENTIFIER_FIELD);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message) {
    return undefined;
  }
  if (message.type === "skarbiec-fill-credentials") {
    const field = targetPasswordField();
    if (field) {
      fillInto(field, message.credentials);
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false, error: "no password field on this page" });
    }
  }
  return undefined;
});

// Alt+Shift+L in a page offers this site's logins at the password field the
// person is in, as the badge does, without reaching for the mouse. A page
// without a password field ignores it and the keystroke goes on to the page.
document.addEventListener("keydown", (event) => {
  if (!event.altKey || !event.shiftKey || event.code !== "KeyL") {
    return;
  }
  const field = targetPasswordField();
  if (!field) {
    return;
  }
  event.preventDefault();
  offerFill(field);
});
