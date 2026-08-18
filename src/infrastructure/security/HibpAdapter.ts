/**
 * HIBP Adapter — implements IBreachMonitor using the HIBP API.
 */
import type { IBreachMonitor } from '../../domain/ports/IBreachMonitor';
import { checkPasswordBreach } from './hibp-service';

export class HibpAdapter implements IBreachMonitor {
  async checkPassword(password: string) {
    const result = await checkPasswordBreach(password);
    return { isBreached: result.isBreached, breachCount: result.breachCount };
  }
}
