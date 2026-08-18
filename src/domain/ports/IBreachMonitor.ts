/**
 * Port interface for breach monitoring services.
 * Uses k-anonymity to check passwords against known data breaches
 * without exposing the full password to the API.
 */
export interface IBreachMonitor {
  checkPassword(password: string): Promise<{ isBreached: boolean; breachCount: number }>;
}
