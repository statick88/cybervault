import { AlarmService } from "./AlarmService";

export class ScanScheduler {
  constructor(private alarmService: AlarmService) {}

  async schedule(intervalHours: number): Promise<void> {
    await this.alarmService.clearAll();
    await this.alarmService.setupPeriodicScan(intervalHours);
  }

  async rescheduleAfterConfigChange(
    newInterval: number,
    oldInterval: number,
  ): Promise<void> {
    if (newInterval !== oldInterval) {
      await this.schedule(newInterval);
    }
  }

  async getNextScan(): Promise<Date | null> {
    return await this.alarmService.getNextScheduledTime();
  }
}
