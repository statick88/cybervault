/**
 * API Server para Cyber Vault
 * Servidor HTTP/HTTPS con seguridad mejorada
 */

import { createServer } from 'http';
import * as https from 'https';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { CryptoService } from '../crypto/crypto-service';
import { Vault } from '../../domain/entities/vault';

// Configuración de seguridad
const SECURITY_CONFIG = {
  HTTPS_ENABLED: process.env.HTTPS_ENABLED === 'true',
  TLS_CERT_PATH: process.env.TLS_CERT_PATH || './certs/server.crt',
  TLS_KEY_PATH: process.env.TLS_KEY_PATH || './certs/server.key',
  CSP: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "blob:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"],
  },
};

// Inicializar servicios
const cryptoService = new CryptoService();

/**
 * Handler para health checks
 */
function handleHealth(req: any, res: any) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'cyber-vault-api',
  }));
}

/**
 * Handler para readiness checks
 */
function handleReady(req: any, res: any) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({
    status: 'ready',
    timestamp: new Date().toISOString(),
  }));
}

/**
 * Handler para crear vault (demo)
 */
async function handleCreateVault(req: any, res: any) {
  let body = '';
  
  req.on('data', (chunk: Buffer) => {
    body += chunk.toString();
  });
  
  req.on('end', async () => {
    try {
      const data = JSON.parse(body);
      
      // Encriptar datos
      const keyPair = await cryptoService.generateKeyPair();
      const encryptedData = await cryptoService.encrypt(data.secret, keyPair.publicKey);
      
      // Crear vault
      const vault = Vault.create({
        name: data.name || 'Demo Vault',
        description: data.description,
        encryptedData: encryptedData,
        encryptionKeyId: 'demo-key-id',
        metadata: {
          encryptedWith: 'AES-GCM-256',
          keyType: 'ECDSA-P-256',
        },
      });
      
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        id: vault.id.toString(),
        name: vault.name,
        createdAt: vault.createdAt.toISOString(),
      }));
    } catch (error) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid request' }));
    }
  });
}

/**
 * Handler principal
 */
async function requestHandler(req: any, res: any) {
  // Configurar headers de seguridad
  const cspString = Object.entries(SECURITY_CONFIG.CSP)
    .map(([key, values]) => `${key} ${values.join(' ')}`)
    .join('; ');
  
  res.setHeader('Content-Security-Policy', cspString);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  const url = new URL(req.url, `http://${req.headers.host}`);
  
  try {
    switch (url.pathname) {
      case '/health':
        handleHealth(req, res);
        break;
        
      case '/ready':
        handleReady(req, res);
        break;
        
      case '/api/v1/vaults':
        if (req.method === 'POST') {
          await handleCreateVault(req, res);
        } else {
          res.writeHead(405, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Method not allowed' }));
        }
        break;
        
      default:
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
    }
  } catch (error) {
    console.error('Error handling request:', error);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal server error' }));
  }
}

/**
 * Iniciar servidor
 */
export function startServer(port: number = 3000) {
  let server: any;
  
  if (SECURITY_CONFIG.HTTPS_ENABLED) {
    try {
      const options = {
        key: readFileSync(resolve(SECURITY_CONFIG.TLS_KEY_PATH)),
        cert: readFileSync(resolve(SECURITY_CONFIG.TLS_CERT_PATH)),
      };
      server = https.createServer(options, requestHandler);
      console.log(`🔒 HTTPS Server started on port ${port}`);
    } catch (error) {
      console.warn('HTTPS certificates not found, falling back to HTTP');
      server = createServer(requestHandler);
      console.log(`⚠️  HTTP Server started on port ${port} (no HTTPS)`);
    }
  } else {
    server = createServer(requestHandler);
    console.log(`🌐 HTTP Server started on port ${port}`);
  }
  
  server.listen(port, () => {
    console.log(`🚀 Cyber Vault API ready at http://localhost:${port}`);
    console.log(`   Health check: http://localhost:${port}/health`);
    console.log(`   Ready check: http://localhost:${port}/ready`);
  });
  
  return server;
}

// Iniciar servidor si ejecutado directamente
if (require.main === module) {
  const port = parseInt(process.env.PORT || '3000', 10);
  startServer(port);
}
