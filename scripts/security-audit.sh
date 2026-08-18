#!/bin/bash
# =============================================================================
# CyberVault Security Audit Script - Fast Version
# =============================================================================

# Don't exit on error - we want to complete all checks
set +e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔐 CyberVault Security Audit${NC}"
echo "========================================"

cd "$(dirname "$0")/.."

PASSED=0
FAILED=0
WARNINGS=0

log_pass() { echo -e "${GREEN}✅ PASS:${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}❌ FAIL:${NC} $1"; ((FAILED++)); }
log_warn() { echo -e "${YELLOW}⚠️  WARN:${NC} $1"; ((WARNINGS++)); }
log_info() { echo -e "${BLUE}ℹ️  INFO:${NC} $1"; }

# 1. Dependencies
echo -e "${BLUE}1. Dependencies${NC}"
[ -f "package-lock.json" ] && log_pass "package-lock.json exists" || log_fail "Missing"

# 2. Build files
echo -e "${BLUE}2. Build Artifacts${NC}"
[ -f "dist/manifest.json" ] && log_pass "Manifest V3 found" || log_fail "Missing manifest"
[ -f "dist/background/auditor.js" ] && log_pass "Background script found" || log_fail "Missing background"
[ -f "dist/ui/popup/popup.js" ] && log_pass "Popup JS found" || log_fail "Missing popup"

# 3. TypeScript
echo -e "${BLUE}3. TypeScript${NC}"
npx tsc --noEmit --skipLibCheck > /dev/null 2>&1 && log_pass "TypeScript compiles" || log_fail "TS errors"

# 4. Crypto
echo -e "${BLUE}4. Crypto${NC}"
grep -q "@noble/curves" package.json && log_pass "Using @noble/curves" || log_warn "Check crypto libs"
! grep -r "createHash.*md5" src/ > /dev/null 2>&1 && log_pass "No MD5" || log_fail "MD5 found"
! grep -r "createHash.*sha1" src/ > /dev/null 2>&1 && log_pass "No SHA1" || log_fail "SHA1 found"

# 5. Manifest
echo -e "${BLUE}5. Manifest${NC}"
grep -q '"manifest_version": 3' dist/manifest.json && log_pass "Manifest V3" || log_fail "Not V3"
grep -q '"content_security_policy"' dist/manifest.json && log_pass "CSP defined" || log_fail "No CSP"

# 6. CI/CD
echo -e "${BLUE}6. CI/CD${NC}"
[ -f ".github/workflows/ci.yml" ] && log_pass "CI/CD exists" || log_fail "No CI/CD"

# 7. Security docs
echo -e "${BLUE}7. Security Documentation${NC}"
[ -f "SECURITY.md" ] && log_pass "SECURITY.md exists" || log_warn "No SECURITY.md"

# Summary
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "Passed: $PASSED | Failed: $FAILED | Warnings: $WARNINGS"
echo -e "${BLUE}========================================${NC}"

[ $FAILED -eq 0 ] && echo -e "${GREEN}🎉 Audit passed!${NC}" || echo -e "${RED}⚠️  Issues found${NC}"
exit $FAILED
