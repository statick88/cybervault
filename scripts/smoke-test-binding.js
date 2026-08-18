#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const BUILD_ROOT = process.env.CRYPTO_BUILD_ROOT
  ? path.resolve(process.env.CRYPTO_BUILD_ROOT)
  : path.resolve(__dirname, "../dist");

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", {
    value: webcrypto,
    configurable: true,
  });
}

if (typeof globalThis.atob !== "function") {
  globalThis.atob = (value) => Buffer.from(value, "base64").toString("binary");
}

if (typeof globalThis.btoa !== "function") {
  globalThis.btoa = (value) => Buffer.from(value, "binary").toString("base64");
}

const store = new Map();

globalThis.chrome = {
  storage: {
    local: {
      async get(keys) {
        if (Array.isArray(keys)) {
          const result = {};
          for (const key of keys) {
            if (store.has(key)) {
              result[key] = store.get(key);
            }
          }
          return result;
        }

        if (typeof keys === "string") {
          return { [keys]: store.get(keys) };
        }

        if (keys && typeof keys === "object") {
          const result = { ...keys };
          for (const [key, value] of store.entries()) {
            result[key] = value;
          }
          return result;
        }

        return Object.fromEntries(store.entries());
      },

      async set(entries) {
        for (const [key, value] of Object.entries(entries)) {
          store.set(key, value);
        }
      },

      async remove(keys) {
        const list = Array.isArray(keys) ? keys : [keys];
        for (const key of list) {
          store.delete(key);
        }
      },
    },
  },
};

const { initializeVault, lockVault } = require(path.join(
  BUILD_ROOT,
  "infrastructure/crypto/master-key-manager.js",
));

const { SubtleCryptoChannelBindingAdapter } = require(path.join(
  BUILD_ROOT,
  "infrastructure/crypto/subtle-crypto-channel-binding-adapter.js",
));

(async () => {
  await initializeVault("SmokeTestMasterKey!123");

  const adapter = new SubtleCryptoChannelBindingAdapter(webcrypto);
  const context = {
    domain: "example.com",
    timestamp: Date.now(),
    nonce: adapter.generateNonce(),
  };

  const signature = await adapter.signChannelBinding(context);

  assert.equal(await adapter.verifyChannelBinding(signature, context), true);
  assert.equal(
    await adapter.verifyChannelBinding(signature, {
      ...context,
      domain: "evil.example.com",
    }),
    false,
  );
  assert.equal(
    await adapter.verifyChannelBinding(signature, {
      ...context,
      timestamp: context.timestamp + 6 * 60 * 1000,
    }),
    false,
  );

  const warmupIterations = Number(process.env.CRYPTO_BENCH_WARMUP ?? 25);
  const measuredIterations = Number(process.env.CRYPTO_BENCH_ITERATIONS ?? 250);

  for (let i = 0; i < warmupIterations; i++) {
    const warmupSignature = await adapter.signChannelBinding(context);
    assert.equal(await adapter.verifyChannelBinding(warmupSignature, context), true);
  }

  const start = performance.now();
  for (let i = 0; i < measuredIterations; i++) {
    const measuredSignature = await adapter.signChannelBinding(context);
    assert.equal(await adapter.verifyChannelBinding(measuredSignature, context), true);
  }
  const elapsedMs = performance.now() - start;
  const averageMs = elapsedMs / measuredIterations;

  console.log(`CRYPTO_LATENCY_METRIC=${averageMs.toFixed(6)} ms`);

  lockVault();
  console.log("channel-binding smoke test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
