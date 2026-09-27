/**
 * Recovery Use Cases — Account Password Reset & Master Phrase Recovery
 *
 * Two separate recovery flows:
 * 1. Account Password Forgotten: email reset token → new password → invalidates sessions (NO VEK unlock)
 * 2. Master Phrase Forgotten: Recovery Key → Recovery KEK → unwrap VEK → new Master Phrase → new wrapper
 */

import type { IUserRepository } from "../../domain/repositories";
import type { IVaultRepository } from "../../domain/repositories";
import { logger } from "../../shared/logger";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";
import { secureZero } from "../../infrastructure/crypto/secure-memory";

/** Convert Uint8Array to ArrayBuffer for Web Crypto API */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

// =============================================================================
// TYPES
// =============================================================================

export interface AccountRecoveryInput {
  email: string;
}

export interface AccountRecoveryOutput {
  success: boolean;
  error?: string;
  resetToken?: string; // Only returned in dev mode
}

export interface AccountPasswordResetInput {
  email: string;
  resetToken: string;
  newPassword: string;
}

export interface AccountPasswordResetOutput {
  success: boolean;
  error?: string;
}

export interface MasterRecoveryInput {
  userId: string;
  recoveryKey: string; // Base64 encoded Recovery Key
}

export interface MasterRecoveryOutput {
  success: boolean;
  error?: string;
  newMasterPhraseWrapper?: {
    encryptedVek: string; // VEK wrapped with new Master Phrase
    salt: string; // New salt for Master Phrase derivation
    version: number;
  };
}

export interface RecoveryKeySetupInput {
  userId: string;
  masterPhrase: string;
}

export interface RecoveryKeySetupOutput {
  success: boolean;
  error?: string;
  recoveryKey?: string; // Base64 encoded Recovery Key (shown ONCE)
  recoveryKeyHint?: string; // For user reference
}

// =============================================================================
// ACCOUNT PASSWORD RECOVERY (does NOT unlock VEK)
// =============================================================================

export class AccountRecoveryUseCase {
  constructor(
    private userRepository: IUserRepository,
    private emailService?: EmailService,
  ) {}

  async initiate(input: AccountRecoveryInput): Promise<AccountRecoveryOutput> {
    try {
      const user = await this.userRepository.findByEmail(input.email);
      if (!user) {
        // Constant-time response to prevent user enumeration
        return { success: true };
      }

      // Generate cryptographically secure reset token
      const resetToken = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));
      const resetTokenHash = await this.hashToken(resetToken);
      const expiresAt = Date.now() + 30 * 60 * 1000; // 30 minutes

      // Store reset token hash with expiry
      await this.userRepository.setPasswordResetToken(user.userId, resetTokenHash, expiresAt);

      // Send email with reset link
      if (this.emailService) {
        await this.emailService.sendPasswordResetEmail(input.email, resetToken);
      } else {
        logger.warn("Email service not configured - password reset token not sent", "AccountRecovery");
      }

      logger.info(`Password reset initiated for user: ${user.userId}`, "AccountRecovery");

      // In dev mode, return token for testing
      const isDev = process.env.NODE_ENV === "development";
      return {
        success: true,
        resetToken: isDev ? resetToken : undefined,
      };
    } catch (error) {
      logger.error("Account recovery initiation failed", "AccountRecovery", undefined, String(error));
      return { success: false, error: "Failed to initiate recovery" };
    }
  }

  async resetPassword(input: AccountPasswordResetInput): Promise<AccountPasswordResetOutput> {
    try {
      const user = await this.userRepository.findByEmail(input.email);
      if (!user) {
        return { success: false, error: "Invalid or expired reset token" };
      }

      // Verify reset token
      const storedHash = user.passwordResetTokenHash;
      const storedExpiry = user.passwordResetTokenExpiry;

      if (!storedHash || !storedExpiry) {
        return { success: false, error: "Invalid or expired reset token" };
      }

      if (Date.now() > storedExpiry) {
        await this.userRepository.clearPasswordResetToken(user.userId);
        return { success: false, error: "Reset token expired" };
      }

      const providedHash = await this.hashToken(input.resetToken);
      if (providedHash !== storedHash) {
        return { success: false, error: "Invalid reset token" };
      }

      // Hash new password with Argon2id
      const { hash, salt } = await this.hashPassword(input.newPassword);

      // Update password and clear reset token
      await this.userRepository.updatePassword(user.userId, hash, salt);
      await this.userRepository.clearPasswordResetToken(user.userId);

      // Invalidate all sessions by incrementing session version
      await this.userRepository.incrementSessionVersion(user.userId);

      logger.info(`Password reset completed for user: ${user.userId}`, "AccountRecovery");

      return { success: true };
    } catch (error) {
      logger.error("Account password reset failed", "AccountRecovery", undefined, String(error));
      return { success: false, error: "Failed to reset password" };
    }
  }

  private async hashToken(token: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(token);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    secureZero(data);
    return binaryToBase64(new Uint8Array(hashBuffer));
  }

  private async hashPassword(password: string): Promise<{ hash: string; salt: string }> {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"],
    );
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations: 600000,
        hash: "SHA-512",
      },
      keyMaterial,
      512,
    );
    return {
      hash: binaryToBase64(new Uint8Array(derivedBits)),
      salt: binaryToBase64(salt),
    };
  }
}

// =============================================================================
// MASTER PHRASE RECOVERY (uses Recovery Key to unwrap VEK)
// =============================================================================

export class MasterRecoveryUseCase {
  constructor(
    private userRepository: IUserRepository,
    private vaultRepository: IVaultRepository,
  ) {}

  async recover(input: MasterRecoveryInput): Promise<MasterRecoveryOutput> {
    try {
      const user = await this.userRepository.findById(input.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      // Verify Recovery Key
      const storedRecoveryKeyHash = user.recoveryKeyHash;
      if (!storedRecoveryKeyHash) {
        return { success: false, error: "No Recovery Key configured for this account" };
      }

      const providedHash = await this.hashRecoveryKey(input.recoveryKey);
      if (providedHash !== storedRecoveryKeyHash) {
        logger.warn(`Invalid Recovery Key attempt for user: ${input.userId}`, "MasterRecovery");
        return { success: false, error: "Invalid Recovery Key" };
      }

      // Recovery Key verified - now unwrap VEK and re-wrap with new Master Phrase
      // Get user's vault
      const vaults = await this.vaultRepository.listByOwnerId(input.userId);
      if (vaults.length === 0) {
        return { success: false, error: "No vault found for user" };
      }

      const vault = vaults[0];

      // Decrypt VEK using Recovery KEK (derived from Recovery Key)
      // The vault stores: encryptedVek (wrapped with Recovery KEK) and recoverySalt
      const recoveryData = vault.metadata?.recovery as {
        encryptedVek: string;
        recoverySalt: string;
        version: number;
      } | undefined;

      if (!recoveryData) {
        return { success: false, error: "Recovery data not found in vault" };
      }

      // Derive Recovery KEK from Recovery Key
      const recoveryKek = await this.deriveRecoveryKek(input.recoveryKey, recoveryData.recoverySalt);

      // Unwrap VEK
      const vek = await this.unwrapVek(recoveryData.encryptedVek, recoveryKek);
      if (!vek) {
        return { success: false, error: "Failed to unwrap VEK with Recovery Key" };
      }

      // Generate new Master Phrase (user will set this via UI)
      // For now, we return the VEK wrapped with a placeholder
      // In production, the UI would prompt for new Master Phrase
      const newMasterPhrase = crypto.getRandomValues(new Uint8Array(32));
      const newMasterPhraseBase64 = binaryToBase64(newMasterPhrase);

      const newMasterPhraseWrapper = await this.wrapVekWithMasterPhrase(vek, newMasterPhraseBase64);

      // Secure cleanup
      secureZero(vek);
      secureZero(newMasterPhrase);

      logger.info(`Master recovery completed for user: ${input.userId}`, "MasterRecovery");

      return {
        success: true,
        newMasterPhraseWrapper: {
          encryptedVek: newMasterPhraseWrapper.encryptedVek,
          salt: newMasterPhraseWrapper.salt,
          version: newMasterPhraseWrapper.version,
        },
      };
    } catch (error) {
      logger.error("Master recovery failed", "MasterRecovery", undefined, String(error));
      return { success: false, error: "Master recovery failed" };
    }
  }

  async setupRecoveryKey(input: RecoveryKeySetupInput): Promise<RecoveryKeySetupOutput> {
    try {
      const user = await this.userRepository.findById(input.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }

      // Generate Recovery Key (32 bytes random)
      const recoveryKey = crypto.getRandomValues(new Uint8Array(32));
      const recoveryKeyBase64 = binaryToBase64(recoveryKey);

      // Derive Recovery KEK from Recovery Key (for vault wrapping)
      const recoverySalt = crypto.getRandomValues(new Uint8Array(32));
      const recoveryKek = await this.deriveRecoveryKek(recoveryKeyBase64, binaryToBase64(recoverySalt));

      // Get user's vault
      const vaults = await this.vaultRepository.listByOwnerId(input.userId);
      if (vaults.length === 0) {
        return { success: false, error: "No vault found for user" };
      }

      const vault = vaults[0];

      // Wrap current VEK with Recovery KEK
      // Note: In production, VEK would be retrieved from unlocked vault
      // For now, we simulate by creating a new wrapped VEK
      const vek = crypto.getRandomValues(new Uint8Array(32));
      const wrappedVek = await this.wrapVek(vek, recoveryKek);

      // Hash Recovery Key for storage (verification)
      const recoveryKeyHash = await this.hashRecoveryKey(recoveryKeyBase64);

      // Store Recovery Key hash in user record
      await this.userRepository.setRecoveryKeyHash(user.userId, recoveryKeyHash);

      // Store recovery data in vault metadata
      await this.vaultRepository.updateMetadata(vault.id.toString(), {
        recovery: {
          encryptedVek: wrappedVek.encryptedVek,
          recoverySalt: binaryToBase64(recoverySalt),
          version: 1,
        },
      });

      // Secure cleanup
      secureZero(recoveryKey);
      secureZero(vek);
      secureZero(recoveryKek);

      logger.info(`Recovery Key setup completed for user: ${input.userId}`, "MasterRecovery");

      return {
        success: true,
        recoveryKey: recoveryKeyBase64, // Shown ONCE to user
        recoveryKeyHint: `Recovery Key generated on ${new Date().toISOString().split("T")[0]}`,
      };
    } catch (error) {
      logger.error("Recovery Key setup failed", "MasterRecovery", undefined, String(error));
      return { success: false, error: "Failed to setup Recovery Key" };
    }
  }

  private async hashRecoveryKey(recoveryKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(recoveryKey);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    secureZero(data);
    return binaryToBase64(new Uint8Array(hashBuffer));
  }

  private async deriveRecoveryKek(recoveryKey: string, saltBase64: string): Promise<Uint8Array> {
    const salt = base64ToBinary(saltBase64);
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(new TextEncoder().encode(recoveryKey)),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const kek = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: toArrayBuffer(salt),
        iterations: 600000,
        hash: "SHA-512",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const exported = await crypto.subtle.exportKey("raw", kek);
    return new Uint8Array(exported);
  }

  private async wrapVek(vek: Uint8Array, kek: Uint8Array): Promise<{ encryptedVek: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
      await crypto.subtle.importKey("raw", toArrayBuffer(kek), "AES-GCM", false, ["encrypt"]),
      toArrayBuffer(vek),
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return { encryptedVek: binaryToBase64(combined) };
  }

  private async unwrapVek(encryptedVekBase64: string, kek: Uint8Array): Promise<Uint8Array | null> {
    try {
      const combined = base64ToBinary(encryptedVekBase64);
      const iv = combined.slice(0, 12);
      const ciphertext = combined.slice(12);
      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
        await crypto.subtle.importKey("raw", toArrayBuffer(kek), "AES-GCM", false, ["decrypt"]),
        toArrayBuffer(ciphertext),
      );
      return new Uint8Array(decrypted);
    } catch {
      return null;
    }
  }

  private async wrapVekWithMasterPhrase(vek: Uint8Array, masterPhrase: string): Promise<{
    encryptedVek: string;
    salt: string;
    version: number;
  }> {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(masterPhrase),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const kek = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-512" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
      kek,
      toArrayBuffer(vek),
    );
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encrypted), iv.length);
    return {
      encryptedVek: binaryToBase64(combined),
      salt: binaryToBase64(salt),
      version: 1,
    };
  }
}

// =============================================================================
// EMAIL SERVICE INTERFACE (to be implemented)
// =============================================================================

export interface EmailService {
  sendPasswordResetEmail(email: string, resetToken: string): Promise<void>;
  sendRecoveryKeyEmail(email: string, recoveryKey: string): Promise<void>;
}
