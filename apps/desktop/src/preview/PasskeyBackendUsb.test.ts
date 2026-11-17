import { assert, describe, it } from "@effect/vitest";
import { vi } from "vite-plus/test";

vi.mock("electron", () => ({ BrowserWindow: vi.fn() }));

import {
  isValidRpId,
  parseAssertion,
  parseDevices,
  parseResidentCredentials,
  parseTokenInfo,
} from "./PasskeyBackendUsb.ts";

const base64 = (bytes: ReadonlyArray<number>) => Buffer.from(bytes).toString("base64");

describe("PasskeyBackendUsb", () => {
  it("reads devices and PIN state from fido2-token output", () => {
    assert.deepStrictEqual(
      parseDevices(
        "ioreg://4295252372: vendor=0x1050, product=0x0406 (Yubico YubiKey FIDO+CCID)\n" +
          "/dev/hidraw5: vendor=0x1050, product=0x0407 (Yubico YubiKey OTP+FIDO+CCID)\n",
      ),
      ["ioreg://4295252372", "/dev/hidraw5"],
    );
    assert.deepStrictEqual(parseDevices(""), []);

    const info = (options: string) =>
      parseTokenInfo(`aaguid: 73bb\noptions: ${options}\nminpinlen: 6\npin retries: 7\n`);
    assert.deepStrictEqual(info("rk, up, noplat, clientPin, credentialMgmtPreview"), {
      hasPin: true,
      pinRetries: 7,
    });
    assert.isFalse(info("rk, up, noplat, noclientPin").hasPin);

    assert.deepStrictEqual(
      parseResidentCredentials(
        `00: ${base64([1, 2, 3])} Jane Doe ${base64([9, 8])} es256 uvopt nopay\n` +
          `01: ${base64([4])}  ${base64([7])} eddsa uvreq nopay\n`,
      ).map(({ credentialId, displayName, userHandle }) => [
        [...credentialId],
        displayName,
        userHandle,
      ]),
      [
        [[1, 2, 3], "Jane Doe", Buffer.from([9, 8]).toString("base64url")],
        [[4], "", Buffer.from([7]).toString("base64url")],
      ],
    );
  });

  it("unwraps the CBOR authenticator data in fido2-assert output", () => {
    const authData = Array.from({ length: 37 }, (_, index) => index);
    const output = (head: ReadonlyArray<number>) =>
      ["Y2Ro", "example.com", base64([...head, ...authData]), base64([0x30, 1, 2])].join("\n");

    const parsed = parseAssertion(output([0x58, 37]));
    assert.deepStrictEqual([...(parsed?.authenticatorData ?? [])], authData);
    assert.deepStrictEqual([...(parsed?.signature ?? [])], [0x30, 1, 2]);
    assert.isDefined(parseAssertion(output([0x59, 0, 37])));
    assert.isUndefined(parseAssertion(output([0x58, 36])));
    assert.isUndefined(parseAssertion(output([0x78, 37])));
    assert.isUndefined(parseAssertion("Y2Ro\nexample.com\n"));
  });

  it("accepts only an RP ID that is the origin's host or a registrable suffix of it", () => {
    const origin = "https://dash.cloudflare.com";
    assert.isTrue(isValidRpId("dash.cloudflare.com", origin));
    assert.isTrue(isValidRpId("cloudflare.com", origin));
    assert.isFalse(isValidRpId("com", origin));
    assert.isFalse(isValidRpId("flare.com", origin));
    assert.isFalse(isValidRpId("example.com", origin));
    assert.isFalse(isValidRpId("github.io", "https://alice.github.io"));
    assert.isFalse(isValidRpId("0.1", "http://127.0.0.1"));
    assert.isTrue(isValidRpId("localhost", "http://localhost:3000"));
  });
});
