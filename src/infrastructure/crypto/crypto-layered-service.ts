/**
 * CryptoService - 4 Layers Implementation
 * Simplified crypto service for MVP
 */

import { ICryptoService } from "../../domain/services";
import { CryptoHash } from "../../domain/value-objects/ids";
import { SecureBuffer, secureZero } from "./secure-memory";
import { randomBytes } from "@noble/hashes/utils";

// ============================================================================
// Layer 1: Basic Cryptography - AES-256-GCM
// ============================================================================
class Layer1Crypto {
  async encrypt(plaintext: string, key: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import key
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(key.padEnd(32, "0").slice(0, 32)),
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );

    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      data,
    );

    // Combine IV + ciphertext
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);

    return btoa(String.fromCharCode(...combined));
  }

  async decrypt(ciphertext: string, key: string): Promise<string> {
    const encoder = new TextEncoder();
    const combined = Uint8Array.from(atob(ciphertext), (c) => c.charCodeAt(0));

    // Extract IV and data
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);

    // Import key
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(key.padEnd(32, "0").slice(0, 32)),
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      data,
    );

    return new TextDecoder().decode(decrypted);
  }

  async hash(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(data),
    );
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async deriveKey(password: string, salt: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"],
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: encoder.encode(salt),
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      256,
    );

    const hashArray = Array.from(new Uint8Array(bits));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}

// ============================================================================
// Layer 2: Authentication - HMAC
// ============================================================================
class Layer2Auth {
  async createHmac(data: string, key: string): Promise<string> {
    const encoder = new TextEncoder();
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(key.padEnd(32, "0").slice(0, 32)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );

    const signature = await crypto.subtle.sign(
      "HMAC",
      cryptoKey,
      encoder.encode(data),
    );

    const hashArray = Array.from(new Uint8Array(signature));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  async verifyHmac(data: string, hmac: string, key: string): Promise<boolean> {
    const computed = await this.createHmac(data, key);
    return computed === hmac;
  }

  async createToken(payload: object, secret: string): Promise<string> {
    const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const body = btoa(JSON.stringify(payload));
    const signature = await this.createHmac(`${header}.${body}`, secret);
    return `${header}.${body}.${signature}`;
  }

  async verifyToken(token: string, secret: string): Promise<object | null> {
    try {
      const [header, body, signature] = token.split(".");
      const valid = await this.verifyHmac(
        `${header}.${body}`,
        signature,
        secret,
      );
      if (valid) {
        return JSON.parse(atob(body));
      }
      return null;
    } catch {
      return null;
    }
  }
}

// ============================================================================
// Layer 3: Secure Storage
// ============================================================================
class Layer3Storage {
  async encryptStorage(data: string, masterKey: string): Promise<string> {
    const layer1 = new Layer1Crypto();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltStr = Array.from(salt)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const key = await layer1.deriveKey(masterKey, saltStr);
    const encrypted = await layer1.encrypt(data, key);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ivStr = Array.from(iv)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Create HMAC
    const layer2 = new Layer2Auth();
    const hmac = await layer2.createHmac(encrypted, key);

    return JSON.stringify({
      ciphertext: encrypted,
      iv: ivStr,
      salt: saltStr,
      tag: hmac,
    });
  }

  async decryptStorage(storage: string, masterKey: string): Promise<string> {
    const layer1 = new Layer1Crypto();
    const layer2 = new Layer2Auth();

    const { ciphertext, iv, salt, tag } = JSON.parse(storage);

    const key = await layer1.deriveKey(masterKey, salt);
    const valid = await layer2.verifyHmac(ciphertext, tag, key);

    if (!valid) {
      throw new Error("Authentication failed - data may be tampered");
    }

    return await layer1.decrypt(ciphertext, key);
  }

  secureWipe(data: Uint8Array): void {
    crypto.getRandomValues(data);
    data.fill(0);
  }
}

// ============================================================================
// Layer 4: Protection - Password Strength & Breach Check
// ============================================================================
class Layer4Protection {
  checkPasswordStrength(password: string): {
    score: number;
    label: string;
    feedback: string[];
  } {
    let score = 0;
    const feedback: string[] = [];

    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;

    if (/[a-z]/.test(password)) score++;
    else feedback.push("Add lowercase letters");

    if (/[A-Z]/.test(password)) score++;
    else feedback.push("Add uppercase letters");

    if (/[0-9]/.test(password)) score++;
    else feedback.push("Add numbers");

    if (/[^a-zA-Z0-9]/.test(password)) score++;
    else feedback.push("Add special characters");

    const labels = ["very-weak", "weak", "medium", "strong", "very-strong"];
    const label = labels[Math.min(Math.floor(score / 2), 4)];

    return { score, label, feedback };
  }

  async checkBreach(password: string): Promise<boolean> {
    // SHA-1 hash for HIBP API
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest(
      "SHA-1",
      encoder.encode(password),
    );
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hash = hashArray
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    try {
      const response = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`,
      );
      if (!response.ok) return false;

      const text = await response.text();
      const lines = text.split("\n");

      for (const line of lines) {
        const [hashSuffix, count] = line.split(":");
        if (hashSuffix.trim() === suffix) {
          return true; // Password found in breaches
        }
      }
      return false;
    } catch {
      return false;
    }
  }
}

// ============================================================================
// Main Crypto Service - Implements ICryptoService
// ============================================================================
export class CryptoLayeredService implements ICryptoService {
  private layer1 = new Layer1Crypto();
  private layer2 = new Layer2Auth();
  private layer3 = new Layer3Storage();
  private layer4 = new Layer4Protection();

  async encrypt(plaintext: string, key: string): Promise<string> {
    return await this.layer1.encrypt(plaintext, key);
  }

  async decrypt(ciphertext: string, key: string): Promise<string> {
    return await this.layer1.decrypt(ciphertext, key);
  }

  async hash(data: string): Promise<string> {
    return await this.layer1.hash(data);
  }

  async deriveKey(password: string, salt: string): Promise<string> {
    return await this.layer1.deriveKey(password, salt);
  }

  // Layer 2 methods
  async createHmac(data: string, key: string): Promise<string> {
    return await this.layer2.createHmac(data, key);
  }

  async verifyHmac(data: string, hmac: string, key: string): Promise<boolean> {
    return await this.layer2.verifyHmac(data, hmac, key);
  }

  // Layer 3 methods
  async encryptStorage(data: string, masterKey: string): Promise<string> {
    return await this.layer3.encryptStorage(data, masterKey);
  }

  async decryptStorage(storage: string, masterKey: string): Promise<string> {
    return await this.layer3.decryptStorage(storage, masterKey);
  }

  // Layer 4 methods
  checkPasswordStrength(password: string): {
    score: number;
    label: string;
    feedback: string[];
  } {
    return this.layer4.checkPasswordStrength(password);
  }

  async checkBreach(password: string): Promise<boolean> {
    return await this.layer4.checkBreach(password);
  }

  // Additional methods for advanced crypto
  async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['encrypt', 'decrypt']
    );
    
    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    
    return {
      publicKey: Buffer.from(publicKey).toString('base64'),
      privateKey: Buffer.from(privateKey).toString('base64'),
    };
  }

  generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  async sign(data: string, privateKey: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyData = Buffer.from(privateKey, 'base64');
    
    const key = await crypto.subtle.importKey(
      'pkcs8',
      keyData,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const signature = await crypto.subtle.sign('RSA-OAEP', key, encoder.encode(data));
    return Buffer.from(signature).toString('base64');
  }

  async verify(data: string, signature: string, publicKey: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const keyData = Buffer.from(publicKey, 'base64');
      
      const key = await crypto.subtle.importKey(
        'spki',
        keyData,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['verify']
      );
      
      return await crypto.subtle.verify(
        'RSA-OAEP',
        key,
        encoder.encode(data),
        Buffer.from(signature, 'base64')
      );
    } catch {
      return false;
    }
  }
}

export const cryptoService = new CryptoLayeredService();
