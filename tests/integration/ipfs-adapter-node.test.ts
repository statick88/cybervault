/**
 * IPFS adapter against a mocked Kubo node.
 *
 * `tests/integration/ipfs-adapter.test.ts` only ever exercises the
 * in-memory fallback: it points the adapter at a black-hole address and
 * asserts the degraded path. Nothing drove the code that runs when a node
 * actually answers — `isHealthy`, the `cat` streaming merge, the
 * breaker/retry wrapper around it, the memory fallback the wrapper falls back
 * to, or the per-CID decrypt. That is where the file's uncovered statements
 * concentrate, and it is also the only way to observe the `IPFS_API_URL`
 * parsing, because `buildApiUrl`'s result is handed to
 * `ipfs-http-client.create({ url })` and nowhere else.
 *
 * The node is a `jest.mock` of `ipfs-http-client`, so the client the adapter
 * builds is our own: content added is content read back, failures are
 * switchable per test, and every URL the adapter derives is recorded.
 */

// `ipfs-http-client` ships no `main`/`exports` entry, so Jest's resolver
// cannot resolve it — the package is ESM-only and the adapter's own
// `await import(...)` fails in Node, which is exactly why the production
// fallback exists. `virtual: true` registers the stub without asking the
// resolver for the real module.
jest.mock(
  "ipfs-http-client",
  () => ({
    create: jest.fn((opts?: { url?: string }) => {
      mockState.createdUrls.push(String(opts?.url));
      return mockClient;
    }),
  }),
  { virtual: true },
);

import { createIPFSAdapter, IPFSAdapter } from "../../src/infrastructure/ipfs/ipfs-adapter";

/* ------------------------------------------------------------------ */
/*  Mock node                                                          */
/* ------------------------------------------------------------------ */

const mockState = {
  createdUrls: [] as string[],
  idOk: true,
  addFails: false,
  catFails: false,
  /** CID → raw bytes the node holds, exactly what `add` received. */
  contents: new Map<string, Uint8Array>(),
  counter: 0,
};

function encode(data: Uint8Array | string): Uint8Array {
  return typeof data === "string" ? new TextEncoder().encode(data) : data;
}

const mockClient = {
  id: jest.fn(async () => {
    if (!mockState.idOk) throw new Error("ECONNREFUSED");
    return { id: "peer-1" };
  }),
  add: jest.fn(async (data: Uint8Array | string) => {
    if (mockState.addFails) throw new Error("unexpected end of stream");
    mockState.counter += 1;
    const cid = `cid-${mockState.counter}`;
    mockState.contents.set(cid, encode(data));
    return { cid: { toString: () => cid }, path: cid, size: 0 };
  }),
  cat: jest.fn((cid: string) => ({
    async *[Symbol.asyncIterator]() {
      const stored = mockState.contents.get(cid);
      if (mockState.catFails || !stored) throw new Error("unexpected end of stream");
      // Two chunks on purpose: the merge loop has to place the second one.
      const mid = Math.max(1, Math.floor(stored.length / 2));
      yield stored.slice(0, mid);
      yield stored.slice(mid);
    },
  })),
  pin: {
    add: jest.fn(async (cid: string) => ({ cid: { toString: () => cid } })),
    rm: jest.fn(async () => undefined),
    ls: jest.fn(async function* () {
      for (const cid of mockState.contents.keys()) yield { cid: { toString: () => cid } };
    }),
  },
};

/* ------------------------------------------------------------------ */
/*  Harness                                                            */
/* ------------------------------------------------------------------ */

const originalIpfsApiUrl = process.env.IPFS_API_URL;

function makeAdapter(): IPFSAdapter {
  return createIPFSAdapter({ host: "127.0.0.1", port: 5001, protocol: "http" });
}

/** Build an adapter and wait for its client promise to settle. */
async function makeLiveAdapter(): Promise<IPFSAdapter> {
  const adapter = makeAdapter();
  await adapter.isHealthy();
  return adapter;
}

/**
 * Build an adapter from `IPFS_API_URL` alone — no explicit config, which
 * would spread over the parsed URL and hide it.
 */
async function makeEnvAdapter(): Promise<IPFSAdapter> {
  const adapter = createIPFSAdapter();
  await adapter.isHealthy();
  return adapter;
}

beforeEach(() => {
  mockState.createdUrls.length = 0;
  mockState.idOk = true;
  mockState.addFails = false;
  mockState.catFails = false;
  mockState.contents.clear();
  mockState.counter = 0;
  delete process.env.IPFS_API_URL;
});

afterAll(() => {
  if (originalIpfsApiUrl === undefined) delete process.env.IPFS_API_URL;
  else process.env.IPFS_API_URL = originalIpfsApiUrl;
});

/* ------------------------------------------------------------------ */
/*  Health                                                             */
/* ------------------------------------------------------------------ */

describe("isHealthy", () => {
  it("answers true for a node that responds to id()", async () => {
    const adapter = makeAdapter();

    await expect(adapter.isHealthy()).resolves.toBe(true);
  });

  it("answers false when id() fails on an otherwise connected client", async () => {
    const adapter = makeAdapter();
    await adapter.isHealthy();

    mockState.idOk = false;

    await expect(adapter.isHealthy()).resolves.toBe(false);
  });

  it("answers false without probing once the breaker has opened", async () => {
    mockState.catFails = true;
    const adapter = await makeLiveAdapter();

    // Five failures is the breaker's default threshold.
    for (let i = 0; i < 5; i++) {
      await adapter.download(`cid-${i}`, false).catch(() => undefined);
    }

    mockState.idOk = false;
    const probesBefore = mockClient.id.mock.calls.length;
    await expect(adapter.isHealthy()).resolves.toBe(false);
    // Never probed: `id()` was rigged to fail, yet nothing reported unhealthy
    // from the probe — the open circuit short-circuits before it.
    expect(mockClient.id.mock.calls.length).toBe(probesBefore);
  });
});

/* ------------------------------------------------------------------ */
/*  Read / write through the node                                      */
/* ------------------------------------------------------------------ */

describe("upload and download through the node", () => {
  it("round-trips plaintext, merging every chunk the node streams back", async () => {
    const adapter = await makeLiveAdapter();

    const cid = await adapter.upload("hello world", false);

    await expect(adapter.download(cid, false)).resolves.toBe("hello world");
    expect(mockState.contents.has(cid)).toBe(true);
  });

  it("decrypts on download when the CID was uploaded encrypted", async () => {
    const adapter = await makeLiveAdapter();

    const cid = await adapter.upload("secret payload", true);

    // The node holds ciphertext; only the adapter still has the key.
    expect(mockState.contents.has(cid)).toBe(true);
    await expect(adapter.download(cid, false)).resolves.not.toBe("secret payload");
    await expect(adapter.download(cid, true)).resolves.toBe("secret payload");
  });

  it("returns ciphertext as-is when no key was recorded for the CID", async () => {
    const adapter = await makeLiveAdapter();

    const cid = await adapter.upload("plaintext stays plaintext", false);

    // `decrypt: true` is the caller's default; with no key on record the
    // adapter must hand the bytes back rather than try a wrong-key decrypt.
    await expect(adapter.download(cid)).resolves.toBe("plaintext stays plaintext");
  });

  it("serves the CID from memory once the node stops answering", async () => {
    mockState.addFails = true;
    const adapter = await makeLiveAdapter();
    const cid = await adapter.upload("cached value", false);

    mockState.catFails = true;

    await expect(adapter.download(cid, false)).resolves.toBe("cached value");
  });

  it("throws when the node fails and memory has nothing either", async () => {
    mockState.catFails = true;
    const adapter = await makeLiveAdapter();

    await expect(adapter.download("QmNothingStored", false)).rejects.toThrow(
      "Data not found",
    );
  });

  it("throws for an unknown CID when there is no node at all", async () => {
    mockState.idOk = false;
    const adapter = makeAdapter();
    await adapter.isHealthy();

    await expect(adapter.download("QmMissing", false)).rejects.toThrow(
      "Data not found",
    );
  });
});

/* ------------------------------------------------------------------ */
/*  IPFS_API_URL parsing                                                */
/* ------------------------------------------------------------------ */

describe("createIPFSAdapter resolves IPFS_API_URL", () => {
  it("honours an explicit port and the path as the API prefix", async () => {
    process.env.IPFS_API_URL = "https://node.example:8443/custom/api";

    await makeEnvAdapter();

    expect(mockState.createdUrls.at(-1)).toBe("https://node.example:8443/custom/api");
  });

  it("defaults to 443 for an https URL that carries no port", async () => {
    process.env.IPFS_API_URL = "https://node.example/";

    await makeEnvAdapter();

    expect(mockState.createdUrls.at(-1)).toBe("https://node.example:443/api/v0");
  });

  it("defaults to 5001 for an http URL that carries no port", async () => {
    process.env.IPFS_API_URL = "http://node.example/";

    await makeEnvAdapter();

    expect(mockState.createdUrls.at(-1)).toBe("http://node.example:5001/api/v0");
  });

  it("falls back to the default node when IPFS_API_URL is not a URL", async () => {
    process.env.IPFS_API_URL = "not a url at all";

    await makeEnvAdapter();

    expect(mockState.createdUrls.at(-1)).toBe("http://127.0.0.1:5001/api/v0");
  });

  it("falls back to the default node when IPFS_API_URL is unset", async () => {
    await makeEnvAdapter();

    expect(mockState.createdUrls.at(-1)).toBe("http://127.0.0.1:5001/api/v0");
  });
});
