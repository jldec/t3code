import { BrowserWindow } from "electron";

const PAGE = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
  :root { color-scheme: light dark; font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  body { margin: 0; padding: 20px; display: flex; flex-direction: column; gap: 10px; }
  h1 { margin: 0; font-size: 14px; font-weight: 600; }
  p { margin: 0; opacity: 0.75; overflow-wrap: anywhere; }
  #error { color: #e5484d; opacity: 1; min-height: 1em; }
  input, select { font: inherit; padding: 6px 8px; border-radius: 6px; border: 1px solid #8886; }
  .buttons { display: flex; justify-content: flex-end; gap: 8px; margin-top: 4px; }
  button { font: inherit; padding: 4px 14px; border-radius: 6px; }
  [hidden] { display: none !important; }
</style>
</head>
<body>
  <h1 id="title">Security key</h1>
  <p id="detail"></p>
  <form id="pin" hidden>
    <input id="pin-input" type="password" autocomplete="off" placeholder="PIN">
    <select id="account-input"></select>
  </form>
  <p id="error"></p>
  <div class="buttons">
    <button id="cancel" type="button">Cancel</button>
    <button id="submit" type="submit" form="pin" hidden>Continue</button>
  </div>
</body>
</html>`;

// Runs in the sheet's main world via executeJavaScript, so the page needs no preload or IPC.
const SCRIPT = `(() => {
  const $ = (id) => document.getElementById(id);
  let onCancel = () => {};
  let resolvePin = null;
  let mode = "pin";
  const cancelled = new Promise((resolve) => { onCancel = resolve; });
  const cancel = () => { resolvePin?.(null); resolvePin = null; onCancel(); };
  $("cancel").onclick = cancel;
  addEventListener("keydown", (event) => { if (event.key === "Escape") cancel(); });
  $("pin").onsubmit = (event) => {
    event.preventDefault();
    const value = mode === "pin" ? $("pin-input").value : Number($("account-input").value);
    if (value !== "" && resolvePin) { resolvePin(value); resolvePin = null; }
  };
  window.securityKeyPrompt = {
    cancelled,
    askPin(detail, error) {
      mode = "pin";
      $("title").textContent = "Enter your security key PIN";
      $("detail").textContent = detail;
      $("error").textContent = error;
      $("pin").hidden = false;
      $("submit").hidden = false;
      $("pin-input").hidden = false;
      $("account-input").hidden = true;
      $("pin-input").value = "";
      $("pin-input").focus();
      return new Promise((resolve) => { resolvePin = resolve; });
    },
    chooseAccount(detail, names) {
      mode = "account";
      $("title").textContent = "Choose a passkey";
      $("detail").textContent = detail;
      $("error").textContent = "";
      $("account-input").replaceChildren(...names.map((name, index) => new Option(name, String(index))));
      $("pin").hidden = false;
      $("submit").hidden = false;
      $("pin-input").hidden = true;
      $("account-input").hidden = false;
      $("account-input").focus();
      return new Promise((resolve) => { resolvePin = resolve; });
    },
    showStatus(title, detail) {
      $("title").textContent = title;
      $("detail").textContent = detail;
      $("error").textContent = "";
      $("pin").hidden = true;
      $("submit").hidden = true;
    },
  };
})()`;

export interface SecurityKeyPrompt {
  /** Resolves undefined when the user cancels. */
  readonly askPin: (error?: string) => Promise<string | undefined>;
  /** Resolves the chosen index, or undefined when the user cancels. */
  readonly chooseAccount: (names: ReadonlyArray<string>) => Promise<number | undefined>;
  readonly showStatus: (title: string) => Promise<void>;
  readonly close: () => void;
}

/** A sheet on the T3 window; Electron has no UI of its own for security key PINs. */
export const openSecurityKeyPrompt = async (
  parent: BrowserWindow,
  relyingPartyId: string,
  onCancel: () => void,
): Promise<SecurityKeyPrompt> => {
  const window = new BrowserWindow({
    parent,
    modal: true,
    show: false,
    width: 380,
    height: 190,
    useContentSize: true,
    resizable: false,
    minimizable: false,
    maximizable: false,
    fullscreenable: false,
    title: "Security key",
    webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false },
  });
  let closed = false;
  window.once("closed", () => {
    if (closed) return;
    closed = true;
    onCancel();
  });
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  const run = <A>(script: string): Promise<A | undefined> =>
    closed
      ? Promise.resolve(undefined)
      : (window.webContents.executeJavaScript(script, true) as Promise<A>).catch(() => undefined);

  await window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(PAGE)}`);
  await run(SCRIPT);
  void run("window.securityKeyPrompt.cancelled").then(() => {
    if (!closed) onCancel();
  });
  if (!closed) window.show();

  const detail = JSON.stringify(relyingPartyId);
  return {
    askPin: async (error) =>
      (await run<string | null>(
        `window.securityKeyPrompt.askPin(${detail}, ${JSON.stringify(error ?? "")})`,
      )) ?? undefined,
    chooseAccount: async (names) =>
      (await run<number | null>(
        `window.securityKeyPrompt.chooseAccount(${detail}, ${JSON.stringify(names)})`,
      )) ?? undefined,
    showStatus: async (title) => {
      await run(`window.securityKeyPrompt.showStatus(${JSON.stringify(title)}, ${detail})`);
    },
    close: () => {
      if (closed) return;
      closed = true;
      window.destroy();
    },
  };
};
