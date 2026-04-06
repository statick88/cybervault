type ActionHandler = (payload?: unknown) => Promise<unknown>;

export class MessageService {
  private handlers: Map<string, ActionHandler> = new Map();

  constructor(handlers?: Record<string, ActionHandler>) {
    if (handlers) {
      this.registerHandlers(handlers);
    }
    this.setupListener();
  }

  registerHandlers(handlers: Record<string, ActionHandler>): void {
    for (const [action, handler] of Object.entries(handlers)) {
      this.handlers.set(action, handler);
    }
  }

  registerAction(action: string, handler: ActionHandler): void {
    this.handlers.set(action, handler);
  }

  unregisterAction(action: string): void {
    this.handlers.delete(action);
  }

  private setupListener(): void {
    chrome.runtime.onMessage.addListener(
      (
        message: { action: string; payload?: unknown },
        _sender,
        sendResponse,
      ) => {
        this.handle(message, _sender)
          .then(sendResponse)
          .catch((error) => {
            sendResponse({ error: error.message });
          });
        return true; // Permite respuesta async
      },
    );
  }

  private async handle(
    message: { action: string; payload?: unknown },
    _sender: chrome.runtime.MessageSender,
  ): Promise<unknown> {
    const handler = this.handlers.get(message.action);
    if (!handler) {
      return { error: `Unknown action: ${message.action}` };
    }
    try {
      return await handler(message.payload);
    } catch (error) {
      console.error(
        "[MessageService] Error handling action",
        message.action,
        error,
      );
      return {
        error:
          error instanceof Error ? error.message : "Error processing request",
      };
    }
  }
}
