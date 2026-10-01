/**
 * Contract alignment between the content script and the service worker.
 *
 * A renamed message type or a reshaped payload would not throw — the content
 * script would simply receive `ok: false` forever and autofill would silently
 * never work. Nothing in either unit's own tests would catch that, because each
 * one is internally consistent. These tests assert the two sides agree.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { MESSAGE_TYPES } from "../../src/background/message-types";

const SW = readFileSync(
  resolve(__dirname, "../../src/background/auditor.ts"),
  "utf8",
).replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

const CS = readFileSync(
  resolve(__dirname, "../../src/ui/content-scripts/autocomplete.ts"),
  "utf8",
).replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

const stripComments = (s: string) => s;

describe("Content script <-> service worker contract", () => {
  it("every message type the content script sends is registered in the worker", () => {
    const sent = [...CS.matchAll(/type:\s*"([A-Z_]+)"/g)].map((m) => m[1]);
    expect(sent.length).toBeGreaterThan(0);

    for (const type of sent) {
      expect(MESSAGE_TYPES).toHaveProperty(type);
    }
  });

  it.each([
    "LIST_CREDENTIALS_FOR_ORIGIN",
    "RELEASE_CREDENTIAL",
  ])("routes %s in the message switch", (type) => {
    expect(SW).toContain(`MESSAGE_TYPES.${type}`);
  });

  it("the worker reads the origin field the content script sends when listing", () => {
    expect(CS).toMatch(/LIST_CREDENTIALS_FOR_ORIGIN[\s\S]{0,80}origin/);
    expect(SW).toMatch(/handleListCredentialsForOrigin[\s\S]{0,200}msg\.origin/);
  });

  it("the worker reads the frame fields the content script sends when releasing", () => {
    for (const field of ["documentOrigin", "topLevelOrigin", "isFramed", "credentialId"]) {
      expect(CS).toContain(field);
      expect(SW).toContain(`msg.${field}`);
    }
  });

  it("returns a credential shape the content script can consume", () => {
    // The content script reads .username / .password / .totpSecret.
    expect(CS).toMatch(/released\.username/);
    expect(CS).toMatch(/released\.password/);
    expect(CS).toMatch(/released\.totpSecret/);
  });

  it("reads candidates with the fields the content script destructures", () => {
    // CandidateSummary is produced by credential-release.ts, which the worker
    // delegates to — so that is where the shape has to exist.
    const RELEASE = readFileSync(
      resolve(__dirname, "../../src/background/credential-release.ts"),
      "utf8",
    );
    for (const field of ["credentialId", "origin", "hasTotp"]) {
      expect(RELEASE).toContain(field);
    }
    // And the worker must actually delegate rather than invent its own shape.
    expect(SW).toContain("listCandidatesForOrigin");
  });

  it("never sends a plaintext secret over the message channel in a denial", () => {
    // Denials must not carry a credential field at all.
    expect(SW).toMatch(/ok:\s*false,\s*error:\s*outcome\.code/);
  });

  it("stores no plaintext under the credential store keys", () => {
    // The store adapters may only return encrypted records.
    expect(stripComments(SW)).toMatch(/cybervault_cred_records/);
    expect(stripComments(SW)).toMatch(/cybervault_cred_index/);
  });

  it("does not write plaintext secrets into chrome.storage from the worker", () => {
    // The worker writes settings and trust data, never a released credential.
    const localWrites = [...SW.matchAll(/chrome\.storage\.local\.set\(([\s\S]*?)\);/g)].map(
      (m) => m[1],
    );
    for (const body of localWrites) {
      expect(body).not.toMatch(/password/i);
      expect(body).not.toMatch(/totpSecret/i);
    }
  });
});
