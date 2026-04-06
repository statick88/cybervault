type PeriodicScanCallback = () => Promise<void>;

export class AlarmService {
  private readonly ALARM_NAMES = {
    PERIODIC_SCAN: "auditor_periodic_scan",
  } as const;

  constructor(private onPeriodicScan: PeriodicScanCallback) {
    chrome.alarms.onAlarm.addListener(this.onAlarm.bind(this));
  }

  async setupPeriodicScan(intervalHours: number): Promise<void> {
    await chrome.alarms.create(this.ALARM_NAMES.PERIODIC_SCAN, {
      periodInMinutes: intervalHours * 60,
    });
  }

  async clearAll(): Promise<void> {
    const alarms = await chrome.alarms.getAll();
    for (const alarm of alarms) {
      if (alarm.name.startsWith("auditor_")) {
        await chrome.alarms.clear(alarm.name);
      }
    }
  }

  async onAlarm(alarm: chrome.alarms.Alarm): Promise<void> {
    if (alarm.name === this.ALARM_NAMES.PERIODIC_SCAN) {
      await this.onPeriodicScan();
    }
  }

  isPeriodicScanAlarm(alarm: chrome.alarms.Alarm): boolean {
    return alarm.name === this.ALARM_NAMES.PERIODIC_SCAN;
  }

  async getNextScheduledTime(): Promise<Date | null> {
    const alarm = await chrome.alarms.get(this.ALARM_NAMES.PERIODIC_SCAN);
    return alarm?.scheduledTime ? new Date(alarm.scheduledTime) : null;
  }
}
