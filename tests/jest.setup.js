/**
 * Jest setup — runs before every test file loads.
 *
 * The API server refuses to start without JWT_SECRET outside of development
 * (see src/infrastructure/api/server.ts), so integration tests must run in a
 * development environment with a test-only secret.
 */
process.env.NODE_ENV = "development";
process.env.JWT_SECRET = process.env.JWT_SECRET || "test-only-secret-change-me-32chars";