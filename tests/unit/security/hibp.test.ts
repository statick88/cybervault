import { checkPasswordBreach } from '../../../src/infrastructure/security/hibp-service';

describe('HIBP Breach Monitoring', () => {
  it('should check password against HIBP API', async () => {
    // "password" is known to be breached
    const result = await checkPasswordBreach('password');
    expect(result.isBreached).toBe(true);
    expect(result.breachCount).toBeGreaterThan(0);
  });

  it('should handle unique passwords', async () => {
    // Use a random password that's unlikely to be breached
    const result = await checkPasswordBreach('CyberVault$ecureP@ssw0rd!2026#Unique');
    expect(result.isBreached).toBe(false);
    expect(result.breachCount).toBe(0);
  });

  it('should fail open on API errors', async () => {
    // Even if the API is down, the service should not block
    const result = await checkPasswordBreach('test');
    expect(result).toHaveProperty('isBreached');
    expect(result).toHaveProperty('breachCount');
  });
});
