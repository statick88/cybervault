/**
 * Lock semantics — the guarantee that a locked vault releases nothing.
 *
 * "Locked" is only meaningful if the key material authorization depends on is
 * actually gone. An earlier version of `handleLockVault` removed the derived
 * session key and the unlock timestamps but left the VEK resident, so the UI
 * showed a locked vault while the service worker could still derive the
 * domain-index key and the per-entry keys and release any credential.
 *
 * These tests pin the required behaviour at the source level, because the
 * defect is a missing key in a remove() call — the kind of thing no
 * higher-level test exercises unless it drives a full service worker.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const SOURCE = readFileSync(
  resolve(__dirname, "../../src/background/auditor.ts"),
  "utf8",
);

function handlerBody(name: string): string {
  const start = SOURCE.indexOf(`async function ${name}`);
  expect(start).toBeGreaterThan(-1);
  const end = SOURCE.indexOf("\n}\n", start);
  return SOURCE.slice(start, end);
}

describe("handleLockVault", () => {
  const body = handlerBody("handleLockVault");

  it("removes the session VEK", () => {
    // This is the assertion that would have caught the real defect.
    expect(body).toMatch(/STORE_KEYS\.SESSION_VEK/);
  });

  it("removes it as part of the session removal, not a local no-op", () => {
    expect(body).toMatch(/chrome\.storage\.session\.remove\(\[[\s\S]*?SESSION_VEK/);
  });

  it("still clears the derived session key and unlock state", () => {
    expect(body).toContain("cybervault_session_key");
    expect(body).toContain("cybervault_unlock_time");
    expect(body).toContain("cybervault_unlock_state");
  });

  it("verifies the VEK is gone instead of assuming removal worked", () => {
    // chrome.storage.session.remove resolves even in some failure modes, so a
    // silent no-op would leave the vault releasable while reporting success.
    expect(body).toMatch(/stillPresent/);
    expect(body).toMatch(/ok:\s*false/);
  });

  it("reports that the VEK was cleared", () => {
    expect(body).toMatch(/vekCleared:\s*true/);
  });

  it("does not clear the encrypted credential store on lock", () => {
    // Locking must not destroy data. Only key material goes.
    expect(body).not.toMatch(/STORE_KEYS\.RECORDS/);
    expect(body).not.toMatch(/STORE_KEYS\.INDEX/);
    expect(body).not.toMatch(/chrome\.storage\.local\.remove/);
  });
});

describe("readSessionVek fails closed", () => {
  const body = handlerBody("readSessionVek");

  it("returns null for a missing key rather than a zero VEK", () => {
    // A zero-filled VEK would derive predictable keys, so "no key" must never
    // become "the key is all zeros".
    expect(body).toMatch(/if\s*\(typeof raw !== "string" \|\| raw === ""\)\s*return null/);
  });

  it("rejects a VEK of the wrong length", () => {
    expect(body).toMatch(/length !== 32/);
  });

  it("returns null instead of throwing when storage is unavailable", () => {
    expect(body).toMatch(/catch\s*\{\s*return null/);
  });
});
