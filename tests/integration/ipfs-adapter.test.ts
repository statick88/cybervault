import { createIPFSAdapter, IPFSAdapter } from "../../src/infrastructure/ipfs/ipfs-adapter";

const IPFS_AVAILABLE = process.env.IPFS_API_URL !== undefined;

const ipfsDescribe = IPFS_AVAILABLE ? describe : describe.skip;
const fallbackDescribe = IPFS_AVAILABLE ? describe.skip : describe;

ipfsDescribe("IPFS Adapter Integration", () => {
  let adapter: IPFSAdapter;

  beforeEach(() => {
    adapter = createIPFSAdapter();
  });

  describe("upload", () => {
    it("uploads a string and returns a CID", async () => {
      const cid = await adapter.upload("hello world", false);
      expect(typeof cid).toBe("string");
      expect(cid.length).toBeGreaterThan(0);
    });

    it("uploads a Uint8Array and returns a CID", async () => {
      const data = new TextEncoder().encode("binary payload");
      const cid = await adapter.upload(data, false);
      expect(typeof cid).toBe("string");
      expect(cid.length).toBeGreaterThan(0);
    });

    it("uploads encrypted data by default", async () => {
      const cid = await adapter.upload("secret data");
      expect(typeof cid).toBe("string");
      expect(cid.length).toBeGreaterThan(0);
    });
  });

  describe("download", () => {
    it("downloads previously uploaded data", async () => {
      const original = "roundtrip test";
      const cid = await adapter.upload(original, false);
      const downloaded = await adapter.download(cid, false);
      expect(downloaded).toBe(original);
    });

    it("throws when CID does not exist", async () => {
      await expect(
        adapter.download("QmNonExistentCid1234567890abcdef", false),
      ).rejects.toThrow();
    });
  });

  describe("list", () => {
    it("lists pinned CIDs after upload", async () => {
      const cid = await adapter.upload("list test", false);
      const cids = await adapter.list();
      expect(cids).toContain(cid);
    });

    it("returns an array when no CIDs exist", async () => {
      const cids = await adapter.list();
      expect(Array.isArray(cids)).toBe(true);
    });
  });

  describe("delete", () => {
    it("unpins a CID", async () => {
      const cid = await adapter.upload("delete me", false);
      const deleted = await adapter.delete(cid);
      expect(deleted).toBe(true);

      const cids = await adapter.list();
      expect(cids).not.toContain(cid);
    });

    it("returns false for non-existent CID", async () => {
      const deleted = await adapter.delete("QmNonExistentCid1234567890abcdef");
      expect(deleted).toBe(false);
    });
  });

  describe("sync", () => {
    it("returns counts without errors", async () => {
      await adapter.upload("sync test", false);
      const result = await adapter.sync();
      expect(result).toHaveProperty("uploaded");
      expect(result).toHaveProperty("downloaded");
      expect(typeof result.uploaded).toBe("number");
      expect(typeof result.downloaded).toBe("number");
    });
  });
});

fallbackDescribe("IPFS Adapter Fallback", () => {
  it("uses in-memory store when IPFS is unavailable", async () => {
    const adapter = createIPFSAdapter({
      host: "192.0.2.1",
      port: 1,
      protocol: "http",
    });

    const cid = await adapter.upload("fallback test", false);
    expect(typeof cid).toBe("string");

    const downloaded = await adapter.download(cid, false);
    expect(downloaded).toBe("fallback test");

    const cids = await adapter.list();
    expect(cids).toContain(cid);

    const deleted = await adapter.delete(cid);
    expect(deleted).toBe(true);

    const cidsAfter = await adapter.list();
    expect(cidsAfter).not.toContain(cid);
  });

  it("sync returns zeros when using fallback", async () => {
    const adapter = createIPFSAdapter({
      host: "192.0.2.1",
      port: 1,
      protocol: "http",
    });

    const result = await adapter.sync();
    expect(result).toEqual({ uploaded: 0, downloaded: 0 });
  });
});
