import { BackgroundAuditorOrchestrator } from "./BackgroundAuditorOrchestrator";
import { StorageService } from "./services/StorageService";
import { AlarmService } from "./services/AlarmService";
import { MessageService } from "./services/MessageService";
import { TabService } from "./services/TabService";
import { ScanScheduler } from "./services/ScanScheduler";
import { NotificationService } from "./services/NotificationService";
import { BreachScanner } from "./scanners/BreachScanner";
import { CredentialScanner } from "./scanners/CredentialScanner";
import { ThreatIntelScanner } from "./scanners/ThreatIntelScanner";
import { BreachDetector } from "./breach-detector";
import { CredentialMonitor } from "./credential-monitor";
import { AuditorConfig } from "./models";

async function initAuditor(): Promise<void> {
  // 1. Inicializar StorageService
  const storageService = new StorageService();

  // 2. Cargar config
  const config: AuditorConfig = await storageService.loadConfig();

  // 3. Inicializar scanners
  const breachDetector = new BreachDetector();
  const breachScanner = new BreachScanner(breachDetector);

  const credentialMonitor = new CredentialMonitor();
  const credentialScanner = new CredentialScanner(credentialMonitor);

  const threatIntelScanner = new ThreatIntelScanner(breachDetector);

  // 4. Notificación
  const notificationService = new NotificationService();

  // 5. Crear orchestrator (scanScheduler se inyecta después)
  const orchestrator = new BackgroundAuditorOrchestrator(
    storageService,
    notificationService,
    breachScanner,
    credentialScanner,
    threatIntelScanner,
    config,
  );

  // 6. ScanScheduler (incluye AlarmService)
  const scanScheduler = new ScanScheduler(
    new AlarmService(async () => {
      await orchestrator.runFullAudit();
    }),
  );
  orchestrator.setScanScheduler(scanScheduler);

  // 7. MessageService con handlers
  new MessageService({
    ping: () => Promise.resolve({ status: "alive", timestamp: Date.now() }),
    run_audit: () => orchestrator.runFullAudit(),
    get_status: () => orchestrator.getStatus(),
    update_config: (payload) =>
      orchestrator.updateConfig(payload as Partial<AuditorConfig>),
    get_history: () => orchestrator.getHistory(),
    clear_history: () => orchestrator.clearHistory(),
  });

  // 8. TabService con callback
  new TabService(
    (findings) => orchestrator.handleTabFindings(findings),
    credentialScanner,
  );

  // 9. Inicializar orchestrator
  await orchestrator.initialize();

  console.log("[Auditor] Background Auditor initialized");
}

// Listeners de Chrome
chrome.runtime.onInstalled.addListener(async (_details) => {
  await initAuditor();
});

// Recarga del service worker
if (typeof chrome !== "undefined") {
  initAuditor().catch(console.error);
}
