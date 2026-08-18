import { dnsNormalize } from "../../../src/domain/utils/dns-normalize";

describe("dnsNormalize", () => {
  describe("lowercasing", () => {
    it("lowercases uppercase hostname", () => {
      expect(dnsNormalize("EXAMPLE.COM")).toBe("example.com");
    });

    it("lowercases mixed-case hostname", () => {
      expect(dnsNormalize("ExAmPlE.CoM")).toBe("example.com");
    });

    it("leaves lowercase unchanged", () => {
      expect(dnsNormalize("example.com")).toBe("example.com");
    });
  });

  describe("trailing dot removal", () => {
    it("removes trailing dot", () => {
      expect(dnsNormalize("example.com.")).toBe("example.com");
    });

    it("removes trailing dot from mixed case", () => {
      expect(dnsNormalize("Example.COM.")).toBe("example.com");
    });

    it("does not remove dots in the middle", () => {
      expect(dnsNormalize("sub.example.com")).toBe("sub.example.com");
    });
  });

  describe("whitespace trimming", () => {
    it("trims leading whitespace", () => {
      expect(dnsNormalize("  example.com")).toBe("example.com");
    });

    it("trims trailing whitespace", () => {
      expect(dnsNormalize("example.com  ")).toBe("example.com");
    });

    it("trims both leading and trailing whitespace", () => {
      expect(dnsNormalize("  example.com  ")).toBe("example.com");
    });

    it("trims tabs", () => {
      expect(dnsNormalize("\texample.com\t")).toBe("example.com");
    });
  });

  describe("combined transformations", () => {
    it("applies lowercase, trim, and trailing dot removal together", () => {
      expect(dnsNormalize("  Example.COM.  ")).toBe("example.com");
    });

    it("handles single character hostname", () => {
      expect(dnsNormalize("A")).toBe("a");
    });

    it("handles hostname with subdomain", () => {
      expect(dnsNormalize("Mail.Google.Com")).toBe("mail.google.com");
    });
  });
});
