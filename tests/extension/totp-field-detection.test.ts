/**
 * TOTP field detection — DOM behaviour.
 *
 * Split from totp-generator.test.ts on purpose: the pure TOTP/HMAC vectors need
 * Node's WebCrypto (`crypto.subtle`), which jsdom does not provide. Mixing both
 * in one file forces a choice between a broken crypto environment and a broken
 * DOM environment. Here we only need a DOM, so jsdom is the right environment
 * and no WebCrypto call is made.
 *
 * @jest-environment jsdom
 */

import { detectTOTPField } from "../../src/ui/content-scripts/totp-generator";

function formWith(html: string): HTMLFormElement {
  const form = document.createElement("form");
  form.innerHTML = html;
  return form;
}

describe("detectTOTPField", () => {
  describe("positive signals", () => {
    it.each([
      ["autocomplete=one-time-code", '<input type="text" autocomplete="one-time-code">'],
      ["name contains totp", '<input type="text" name="totp_code">'],
      ["name contains 2fa", '<input type="text" name="2fa_token">'],
      ["name contains mfa", '<input type="text" name="mfa-code">'],
      ["name contains otp", '<input type="text" name="otp">'],
      ["id contains totp", '<input type="text" id="totp-input">'],
      ["id contains otp", '<input type="text" id="otp-input">'],
      ["placeholder contains codigo", '<input type="text" placeholder="Ingrese su codigo">'],
      ["placeholder contains código", '<input type="text" placeholder="Ingrese su código">'],
      ["placeholder contains code", '<input type="text" placeholder="Verification code">'],
    ])("detects a TOTP field via %s", (_label, html) => {
      const field = detectTOTPField(formWith(html));
      expect(field).not.toBeNull();
      expect(field).toBeInstanceOf(HTMLInputElement);
    });

    it("accepts tel and number input types", () => {
      expect(detectTOTPField(formWith('<input type="tel" name="totp">'))).not.toBeNull();
      expect(detectTOTPField(formWith('<input type="number" name="otp">'))).not.toBeNull();
    });

    it("matches case-insensitively", () => {
      expect(detectTOTPField(formWith('<input type="text" name="TOTP">'))).not.toBeNull();
      expect(detectTOTPField(formWith('<input type="text" name="Totp">'))).not.toBeNull();
    });

    it("returns the matching input, not merely a truthy value", () => {
      const field = detectTOTPField(formWith('<input type="text" name="totp" id="the-one">'));
      expect(field?.id).toBe("the-one");
    });
  });

  describe("negative signals", () => {
    it.each([
      ["plain username", '<input type="text" name="username">'],
      ["plain email", '<input type="email" name="email">'],
      ["password field", '<input type="password" name="password">'],
      ["empty form", ""],
    ])("does not claim a %s field", (_label, html) => {
      expect(detectTOTPField(formWith(html))).toBeNull();
    });

    it("ignores inputs outside the form", () => {
      document.body.innerHTML = '<input type="text" name="totp">';
      const form = document.createElement("form");
      expect(detectTOTPField(form)).toBeNull();
      document.body.innerHTML = "";
    });
  });

  describe("selection among multiple fields", () => {
    it("prefers the TOTP field over an earlier ordinary text field", () => {
      const form = formWith(
        '<input type="text" name="username"><input type="text" name="otp_code">',
      );
      const field = detectTOTPField(form);
      expect(field?.name).toBe("otp_code");
    });

    it("returns the first TOTP field when several match", () => {
      const form = formWith(
        '<input type="text" name="totp_first"><input type="text" name="totp_second">',
      );
      const field = detectTOTPField(form);
      expect(field?.name).toBe("totp_first");
    });
  });
});
