/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/tests"],
  testMatch: ["**/*.test.ts"],
  setupFiles: ["<rootDir>/tests/jest.setup.js"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
  transform: {
    // `plus/api/server.ts` carries 4 pre-existing type errors that are part of
    // the tracked `tsc --noEmit` baseline (809). ts-jest re-reports diagnostics
    // for every file it transforms, so any test that drives the real Plus HTTP
    // route would fail to *compile* on errors that predate the change under
    // test. The `tsc` gate still covers this file; this carve-out only stops
    // the test runner from re-stating them. No other file is excluded.
    "^.+\\.tsx?$": ["ts-jest", {
      diagnostics: { exclude: ["**/plus/api/server.ts"] },
    }],
    "^.+\\.js$": "babel-jest",
  },
  transformIgnorePatterns: [
    "/node_modules/(?!@noble/)",
  ],
  // Must mirror what SonarQube actually gates, or the reported coverage is a
  // measurement of a different project than the one being scored.
  // sonar.sources=src,plus with **/plus/admin/** excluded, and
  // sonar.coverage.exclusions=**\/*.test.ts,**\/*.spec.ts,**\/mocks/**.
  // Measuring only src/domain/** left Sonar scoring every src/infrastructure,
  // src/application and plus/ file as 0% because no data was ever collected
  // for them, which is what kept the new_coverage gate in ERROR.
  collectCoverageFrom: [
    "src/**/*.ts",
    "plus/**/*.ts",
    "!**/plus/admin/**",
    "!**/*.test.ts",
    "!**/*.spec.ts",
    "!**/mocks/**",
    "!**/index.ts",
    "!**/*.d.ts",
  ],
};
