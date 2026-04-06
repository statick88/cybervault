export default {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  collectCoverageFrom: ["src/**/*.ts", "!src/**/*.d.ts", "!src/**/index.ts"],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterEnv: ["<rootDir>/tests/setup.ts"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
    "^@noble/hashes/(.*)$": "<rootDir>/node_modules/@noble/hashes/$1.js",
  },
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      { useESM: true, tsconfig: "tsconfig.test.json" },
    ],
    "^.+\\.js$": "babel-jest",
  },
  extensionsToTreatAsEsm: [".ts"],
  transformIgnorePatterns: [
    "/node_modules/(?!(?:@noble/hashes|@noble/curves|@noble/post-quantum|cuid2|@paralleldrive|formidable)/)",
  ],
};
