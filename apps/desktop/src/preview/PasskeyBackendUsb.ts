// @effect-diagnostics globalTimers:off - Ceremonies settle inside IPC handlers, outside an Effect runtime.
// @effect-diagnostics nodeBuiltinImport:off - Runs libfido2 tools from a plain IPC promise, like the macOS backend.
import * as NodeChildProcess from "node:child_process";
import * as NodeCrypto from "node:crypto";
import * as NodeNet from "node:net";

import type { PasskeyBackend } from "./PasskeyBackend.ts";
import { isPublicSuffix } from "./PasskeyBackendMac.ts";
import { SECURITY_KEY_ABSENT, type PasskeyCeremonyResult } from "./PasskeyBridge.ts";
import { openSecurityKeyPrompt, type SecurityKeyPrompt } from "./SecurityKeyPrompt.ts";

export interface Fido2Tools {
  readonly assert: string;
  readonly token: string;
}

interface ToolResult {
  readonly ok: boolean;
  readonly stdout: string;
  readonly fidoError: string | undefined;
}

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_TIMEOUT_MS = 10 * 60 * 1000;

const notAllowed: PasskeyCeremonyResult = { success: false, error: "NotAllowedError" };

const bytesOf = (value: BufferSource) =>
  Buffer.from(
    ArrayBuffer.isView(value)
      ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
      : new Uint8Array(value),
  );

const isBufferSource = (value: unknown): value is BufferSource =>
  value instanceof ArrayBuffer || ArrayBuffer.isView(value);

export const isValidRpId = (rpId: string, origin: string) => {
  const host = new URL(origin).hostname;
  if (rpId === host) return !isPublicSuffix(rpId);
  return (
    NodeNet.isIP(host) === 0 &&
    rpId.length > 0 &&
    host.endsWith(`.${rpId}`) &&
    !isPublicSuffix(rpId)
  );
};

/** Device paths from `fido2-token -L`, such as `ioreg://4295252372` or `/dev/hidraw5`. */
export const parseDevices = (output: string) =>
  output
    .split("\n")
    .map((line) => line.slice(0, line.indexOf(": ")).trim())
    .filter((path) => path.length > 0);

/** `fido2-token -I` lists `clientPin` once a PIN is set and `noclientPin` before. */
export const parseTokenInfo = (output: string) => {
  const options = new Set(
    (/^options: (.*)$/mu.exec(output)?.[1] ?? "").split(",").map((option) => option.trim()),
  );
  const retries = /^pin retries: (\d+)$/mu.exec(output)?.[1];
  return {
    hasPin: options.has("clientPin"),
    pinRetries: retries === undefined ? undefined : Number(retries),
  };
};

/** `fido2-token -L -k <rp>` lines: `NN: <cred id> <display name> <user id> <type> <prot> <pay>`. */
export const parseResidentCredentials = (output: string) =>
  output.split("\n").flatMap((line) => {
    const match = /^\d+: (\S+) (.*) (\S*) \S+ \S+ \S+$/u.exec(line.trim());
    if (!match) return [];
    const [, id = "", displayName = "", userId = ""] = match;
    return [
      {
        credentialId: Buffer.from(id, "base64"),
        displayName,
        userHandle: Buffer.from(userId, "base64").toString("base64url"),
      },
    ];
  });

/** fido2-assert prints authenticator data wrapped in a CBOR byte string. */
const unwrapCborBytes = (bytes: Uint8Array) => {
  const head = bytes[0];
  if (head === undefined || head >> 5 !== 2) return undefined;
  const info = head & 31;
  const size = info < 24 ? 0 : info <= 27 ? 1 << (info - 24) : -1;
  if (size < 0 || bytes.length < 1 + size) return undefined;
  let length = info < 24 ? info : 0;
  for (let index = 1; index <= size; index++) length = length * 256 + (bytes[index] ?? 0);
  return bytes.length === 1 + size + length ? bytes.slice(1 + size) : undefined;
};

/** Lines 3 and 4 of `fido2-assert -G` output: CBOR authenticator data and the signature. */
export const parseAssertion = (output: string) => {
  const [, , authData, signature] = output.trim().split("\n");
  if (authData === undefined || signature === undefined) return undefined;
  const authenticatorData = unwrapCborBytes(Buffer.from(authData, "base64"));
  return authenticatorData === undefined
    ? undefined
    : {
        authenticatorData: Buffer.from(authenticatorData),
        signature: Buffer.from(signature, "base64"),
      };
};

const runTool = (
  command: string,
  args: ReadonlyArray<string>,
  options: { readonly input?: string; readonly stdin?: string; readonly signal: AbortSignal },
) =>
  new Promise<ToolResult>((resolve) => {
    // A new session has no controlling tty, so fido2-assert reads the PIN from stdin.
    const child = NodeChildProcess.spawn(command, args, {
      detached: true,
      signal: options.signal,
      stdio: ["pipe", "pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (chunk: Buffer) => (stdout += chunk.toString()));
    child.stderr?.on("data", (chunk: Buffer) => (stderr += chunk.toString()));
    child.on("error", () => resolve({ ok: false, stdout, fidoError: undefined }));
    child.on("close", (code) =>
      resolve({ ok: code === 0, stdout, fidoError: /FIDO_ERR_[A-Z_]+/u.exec(stderr)?.[0] }),
    );
    const fd3 = child.stdio[3];
    if (fd3 && "end" in fd3) fd3.end(options.input ?? "");
    child.stdin?.end(options.stdin ?? "");
  });

/**
 * USB security keys through libfido2's command line tools. Electron's built-in WebAuthn
 * cannot ask for a security key PIN, so a key with a PIN fails there.
 */
export const makeUsbPasskeyBackend = (tools: Fido2Tools): PasskeyBackend => ({
  create: async () => ({ success: false, error: "NotSupportedError" }),
  get: async (publicKey, context): Promise<PasskeyCeremonyResult> => {
    if (!isBufferSource(publicKey.challenge)) return { success: false, error: "TypeError" };
    const rpId = publicKey.rpId ?? new URL(context.origin).hostname;
    if (!isValidRpId(rpId, context.origin)) return { success: false, error: "SecurityError" };
    const credentials = (
      Array.isArray(publicKey.allowCredentials) ? publicKey.allowCredentials : []
    )
      .filter((credential) => credential?.type === "public-key" && isBufferSource(credential.id))
      .map((credential) => bytesOf(credential.id));

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: "webauthn.get",
        challenge: bytesOf(publicKey.challenge).toString("base64url"),
        origin: context.origin,
        crossOrigin: false,
      }),
    );
    const clientDataHash = NodeCrypto.createHash("sha256").update(clientDataJSON).digest("base64");
    const inputFor = (credential: Buffer) =>
      `${clientDataHash}\n${rpId}\n${credential.toString("base64")}\n`;

    const controller = new AbortController();
    const { signal } = controller;
    const timeout = setTimeout(
      () => controller.abort(),
      typeof publicKey.timeout === "number" && publicKey.timeout > 0
        ? Math.min(publicKey.timeout, MAX_TIMEOUT_MS)
        : DEFAULT_TIMEOUT_MS,
    );
    let prompt: SecurityKeyPrompt | undefined;
    const showPrompt = async () => {
      prompt ??= await openSecurityKeyPrompt(context.hostWindow, rpId, () => controller.abort());
      return prompt;
    };

    try {
      const device = parseDevices((await runTool(tools.token, ["-L"], { signal })).stdout)[0];
      if (device === undefined) return { success: false, error: SECURITY_KEY_ABSENT };

      const info = parseTokenInfo((await runTool(tools.token, ["-I", device], { signal })).stdout);
      const verification = publicKey.userVerification ?? "preferred";
      const discoverable = credentials.length === 0;
      // Listing the key's credentials for a site needs a PIN.
      if ((verification === "required" || discoverable) && !info.hasPin) return notAllowed;
      const usePin = info.hasPin && (discoverable || verification !== "discouraged");

      let pin: string | undefined;
      let pinError: string | undefined;
      const ensurePin = async () => {
        if (usePin && pin === undefined) pin = await (await showPrompt()).askPin(pinError);
        return !usePin || pin !== undefined;
      };
      const rejectPin = async () => {
        const { pinRetries } = parseTokenInfo(
          (await runTool(tools.token, ["-I", device], { signal })).stdout,
        );
        pin = undefined;
        pinError = pinRetries === undefined ? "Wrong PIN." : `Wrong PIN. ${pinRetries} tries left.`;
      };

      let candidates: ReadonlyArray<{ readonly id: Buffer; readonly userHandle: string }>;
      if (discoverable) {
        // fido2-assert -r omits credential IDs, so list the site's credentials first.
        let listed: ToolResult | undefined;
        while (!signal.aborted) {
          if (!(await ensurePin())) return notAllowed;
          listed = await runTool(tools.token, ["-L", "-k", rpId, device], {
            stdin: `${pin}\n`,
            signal,
          });
          if (listed.fidoError !== "FIDO_ERR_PIN_INVALID") break;
          await rejectPin();
        }
        const accounts = listed?.ok ? parseResidentCredentials(listed.stdout) : [];
        const choice =
          accounts.length > 1
            ? await (
                await showPrompt()
              ).chooseAccount(
                accounts.map((account, index) => account.displayName || `Passkey ${index + 1}`),
              )
            : 0;
        const account = choice === undefined ? undefined : accounts[choice];
        if (!account) return notAllowed;
        candidates = [{ id: account.credentialId, userHandle: account.userHandle }];
      } else {
        // Probing without user presence finds which allowed credential lives on this key.
        let present = credentials;
        if (credentials.length > 1) {
          present = [];
          for (const credential of credentials) {
            const probe = await runTool(
              tools.assert,
              ["-G", "-t", "up=false", "-i", "/dev/fd/3", device],
              { input: inputFor(credential), signal },
            );
            if (probe.ok) present.push(credential);
          }
          if (present.length === 0) present = credentials;
        }
        candidates = present.map((id) => ({ id, userHandle: "" }));
      }

      let index = 0;
      while (index < candidates.length && !signal.aborted) {
        const credential = candidates[index];
        if (credential === undefined) break;
        if (!(await ensurePin())) return notAllowed;
        await (await showPrompt()).showStatus("Touch your security key");
        const result = await runTool(
          tools.assert,
          ["-G", "-t", "up=true", ...(usePin ? ["-v"] : []), "-i", "/dev/fd/3", device],
          {
            input: inputFor(credential.id),
            ...(pin === undefined ? {} : { stdin: `${pin}\n` }),
            signal,
          },
        );
        if (result.ok) {
          const assertion = parseAssertion(result.stdout);
          if (!assertion) return notAllowed;
          return {
            success: true,
            data: {
              credentialId: credential.id.toString("base64url"),
              clientDataJSON: clientDataJSON.toString("base64url"),
              authenticatorData: assertion.authenticatorData.toString("base64url"),
              signature: assertion.signature.toString("base64url"),
              userHandle: credential.userHandle,
            },
          };
        }
        if (result.fidoError === "FIDO_ERR_PIN_INVALID") {
          await rejectPin();
          continue;
        }
        if (result.fidoError !== "FIDO_ERR_NO_CREDENTIALS") return notAllowed;
        index++;
      }
      return notAllowed;
    } finally {
      clearTimeout(timeout);
      prompt?.close();
      controller.abort();
    }
  },
});
