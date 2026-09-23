# CyberVault — Vault Flows Testing Guide

## Prerequisites

1. **Server running** on `192.168.100.242:3010`
2. **Plugin installed** in Chrome from `cybervault-plugin.tar.gz`
3. **Test user**: `admin@cybervault.test` / `CyberVault#2026!`

## Testing from 192.168.100.179

### Step 1: Access the Web App

Open Chrome and navigate to:
```
http://192.168.100.242:3010/auth.html
```

### Step 2: Login

1. Enter email: `admin@cybervault.test`
2. Enter password: `CyberVault#2026!`
3. Click "Iniciar Sesión"
4. **Expected**: Redirect to `vault.html`

### Step 3: Vault Unlock (Web App)

1. On the vault page, enter your passphrase
2. Click "Desbloquear Vault"
3. **Expected**: Vault unlocks and shows credential list (may be empty initially)

### Step 4: Plugin Installation

1. Extract `cybervault-plugin.tar.gz`:
   ```bash
   tar -xzf cybervault-plugin.tar.gz
   ```
2. Open Chrome → `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked"
5. Select the extracted folder
6. **Expected**: CyberVault icon appears in toolbar

### Step 5: Plugin Login

1. Click the CyberVault icon
2. Enter credentials: `admin@cybervault.test` / `CyberVault#2026!`
3. Click "Iniciar Sesión"
4. **Expected**: Login successful, vault lock screen appears

### Step 6: Plugin Vault Unlock

1. Enter your passphrase
2. Click "Desbloquear"
3. **Expected**: Vault unlocks, shows credential list

### Step 7: Auto-Lock Test

1. Wait 30 minutes (or change timeout in code for testing)
2. **Expected**: Vault automatically locks

## API Endpoints (for manual testing)

### Login
```bash
curl -X POST http://192.168.100.242:3010/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@cybervault.test","password":"CyberVault#2026!"}'
```

### Get Vaults
```bash
curl -X GET http://192.168.100.242:3010/api/v1/vaults \
  -H "Authorization: Bearer <token>"
```

### Unlock Vault
```bash
curl -X POST http://192.168.100.242:3010/api/v1/vaults/<vault-id>/unlock \
  -H "Authorization: Bearer <token>"
```

## Troubleshooting

### CORS Issues
- Ensure you're accessing via `http://192.168.100.242:3010` (not `https`)
- Check browser console for CORS errors

### Plugin Not Loading
- Verify all files are extracted correctly
- Check Chrome DevTools for errors
- Ensure `manifest.json` is valid

### Vault Not Unlocking
- Check browser console for crypto errors
- Verify passphrase matches the one used during vault creation
- Ensure PBKDF2 parameters match (600k iterations, SHA-512)

## Security Notes

- Passphrase is **NEVER** sent to the server
- All decryption happens client-side using Web Crypto API
- Tokens are stored in `chrome.storage.local`
- Unlock state persists for 30 minutes in `chrome.storage.session`
