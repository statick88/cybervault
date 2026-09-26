/**
 * Email Service Interface — CyberVault Plus
 *
 * Interface for sending emails (challenge notifications, audit alerts, etc.)
 * Implementations: SMTP, SendGrid, Mailgun, SES, etc.
 */

export interface IEmailService {
  /**
   * Send challenge email with single-use URL
   */
  sendChallengeEmail(
    email: string,
    challengeUrl: string,
    expiresInMinutes: number,
  ): Promise<void>;

  /**
   * Send audit alert email (optional)
   */
  sendAuditAlert?(email: string, alert: { event: string; details: string }): Promise<void>;
}

/**
 * No-op email service for testing/development
 */
export class NoOpEmailService implements IEmailService {
  async sendChallengeEmail(email: string, challengeUrl: string, expiresInMinutes: number): Promise<void> {
    console.log(`[NoOpEmailService] Challenge email to ${email}: ${challengeUrl} (expires in ${expiresInMinutes} min)`);
  }

  async sendAuditAlert(email: string, alert: { event: string; details: string }): Promise<void> {
    console.log(`[NoOpEmailService] Audit alert to ${email}: ${alert.event} - ${alert.details}`);
  }
}

/**
 * Console email service for development (logs to console)
 */
export class ConsoleEmailService implements IEmailService {
  async sendChallengeEmail(email: string, challengeUrl: string, expiresInMinutes: number): Promise<void> {
    console.log(`\n=== CHALLENGE EMAIL ===`);
    console.log(`To: ${email}`);
    console.log(`Challenge URL: ${challengeUrl}`);
    console.log(`Expires in: ${expiresInMinutes} minutes`);
    console.log(`========================\n`);
  }

  async sendAuditAlert(email: string, alert: { event: string; details: string }): Promise<void> {
    console.log(`\n=== AUDIT ALERT ===`);
    console.log(`To: ${email}`);
    console.log(`Event: ${alert.event}`);
    console.log(`Details: ${alert.details}`);
    console.log(`=====================\n`);
  }
}

/**
 * SMTP email service (production-ready placeholder)
 */
export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
  from: string;
}

export class SmtpEmailService implements IEmailService {
  private config: SmtpConfig;
  private transporter: any; // nodemailer transporter

  constructor(config: SmtpConfig) {
    this.config = config;
    // In real implementation, initialize nodemailer transporter here
  }

  async sendChallengeEmail(email: string, challengeUrl: string, expiresInMinutes: number): Promise<void> {
    // In real implementation:
    // await this.transporter.sendMail({
    //   from: this.config.from,
    //   to: email,
    //   subject: 'CyberVault Plus - Action Required: Authentication Challenge',
    //   html: this.generateChallengeHtml(challengeUrl, expiresInMinutes),
    // });
    console.log(`[SmtpEmailService] Would send challenge email to ${email}`);
  }

  async sendAuditAlert(email: string, alert: { event: string; details: string }): Promise<void> {
    // In real implementation:
    // await this.transporter.sendMail({
    //   from: this.config.from,
    //   to: email,
    //   subject: 'CyberVault Plus - Security Alert',
    //   html: this.generateAlertHtml(alert),
    // });
    console.log(`[SmtpEmailService] Would send audit alert to ${email}`);
  }

  private generateChallengeHtml(url: string, minutes: number): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2>CyberVault Plus - Authentication Challenge</h2>
        <p>A step-up authentication has been requested for your account.</p>
        <p>Please click the link below to complete the challenge:</p>
        <p><a href="${url}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Complete Challenge</a></p>
        <p>This link expires in <strong>${minutes} minutes</strong> and can only be used once.</p>
        <p>If you did not request this, please contact your administrator immediately.</p>
        <hr>
        <small>CyberVault Plus Security Team</small>
      </div>
    `;
  }

  private generateAlertHtml(alert: { event: string; details: string }): string {
    return `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #dc3545;">CyberVault Plus - Security Alert</h2>
        <p><strong>Event:</strong> ${alert.event}</p>
        <p><strong>Details:</strong> ${alert.details}</p>
        <p>Please review this activity in the admin panel.</p>
        <hr>
        <small>CyberVault Plus Security Team</small>
      </div>
    `;
  }
}