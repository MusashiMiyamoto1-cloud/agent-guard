#!/bin/bash

# molt-guard.sh - Lightweight triage tool for agent skills
# Part of Agent Guard security framework
# Usage: ./molt-guard.sh <target-directory>

set -e

VERSION="0.1.0"
TARGET="${1:-.}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  ${BOLD}🛡 MOLT-GUARD${NC}${CYAN}  v${VERSION}                       ║${NC}"
echo -e "${CYAN}║  Quick Security Triage                        ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"
echo

if [ ! -d "$TARGET" ]; then
    echo -e "${RED}[!] Error: Directory not found: $TARGET${NC}"
    exit 1
fi

echo -e "${GRAY}Scanning: $(realpath "$TARGET")${NC}"
echo

ISSUES=0

# 1. Check for manifest
echo -e "${BOLD}[1/6] Manifest Check${NC}"
if [ -f "$TARGET/skill.manifest.json" ]; then
    echo -e "  ${GREEN}[✓] skill.manifest.json present${NC}"
    
    # Validate accountability root
    if grep -q '"accountability"' "$TARGET/skill.manifest.json" 2>/dev/null; then
        echo -e "  ${GREEN}[✓] Human accountability chain defined${NC}"
    else
        echo -e "  ${YELLOW}[!] Missing accountability root - no human accountability${NC}"
        ((ISSUES++))
    fi
else
    echo -e "  ${RED}[!] CRITICAL: Skill is UNSIGNED and OPAQUE${NC}"
    echo -e "  ${GRAY}    Add skill.manifest.json with permissions${NC}"
    ((ISSUES+=5))
fi
echo

# 2. Check for secrets
echo -e "${BOLD}[2/6] Secret Detection${NC}"
SECRETS=$(grep -rE "(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16})" "$TARGET" 2>/dev/null | head -5 || true)
if [ -n "$SECRETS" ]; then
    echo -e "  ${RED}[!] CRITICAL: API keys/tokens found!${NC}"
    echo "$SECRETS" | while read -r line; do
        echo -e "  ${GRAY}    $line${NC}" | head -c 100
        echo "..."
    done
    ((ISSUES+=10))
else
    echo -e "  ${GREEN}[✓] No obvious secrets detected${NC}"
fi
echo

# 3. Check for exfiltration URLs
echo -e "${BOLD}[3/6] Exfiltration Check${NC}"
EXFIL=$(grep -rE "(webhook\.site|requestbin\.com|ngrok\.io|pipedream\.net)" "$TARGET" 2>/dev/null || true)
if [ -n "$EXFIL" ]; then
    echo -e "  ${RED}[!] CRITICAL: Exfiltration URLs found!${NC}"
    echo "$EXFIL" | head -3 | while read -r line; do
        echo -e "  ${GRAY}    $line${NC}"
    done
    ((ISSUES+=10))
else
    echo -e "  ${GREEN}[✓] No exfiltration patterns found${NC}"
fi
echo

# 4. Check for shell execution
echo -e "${BOLD}[4/6] Shell Execution Check${NC}"
SHELL_EXEC=$(grep -rE "(child_process|execSync|spawn\(|subprocess|os\.system)" "$TARGET" --include="*.js" --include="*.ts" --include="*.py" 2>/dev/null || true)
if [ -n "$SHELL_EXEC" ]; then
    echo -e "  ${YELLOW}[!] Shell execution capability detected${NC}"
    echo "$SHELL_EXEC" | head -3 | while read -r line; do
        echo -e "  ${GRAY}    $(echo "$line" | cut -c1-80)...${NC}"
    done
    ((ISSUES+=3))
else
    echo -e "  ${GREEN}[✓] No shell execution patterns${NC}"
fi
echo

# 5. Check for dangerous eval
echo -e "${BOLD}[5/6] Code Injection Check${NC}"
EVAL=$(grep -rE "(eval\(|new Function\(|exec\(compile)" "$TARGET" --include="*.js" --include="*.ts" --include="*.py" 2>/dev/null || true)
if [ -n "$EVAL" ]; then
    echo -e "  ${RED}[!] Dangerous eval() usage detected${NC}"
    ((ISSUES+=5))
else
    echo -e "  ${GREEN}[✓] No eval patterns${NC}"
fi
echo

# 6. Generate integrity hash
echo -e "${BOLD}[6/6] Integrity Lock${NC}"
LOCK_FILE="$TARGET/skill.lock"
if command -v sha256sum &> /dev/null; then
    find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.json" -o -name "*.md" \) -exec sha256sum {} + 2>/dev/null | sort > "$LOCK_FILE"
    echo -e "  ${GREEN}[✓] Generated $LOCK_FILE${NC}"
elif command -v shasum &> /dev/null; then
    find "$TARGET" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.py" -o -name "*.json" -o -name "*.md" \) -exec shasum -a 256 {} + 2>/dev/null | sort > "$LOCK_FILE"
    echo -e "  ${GREEN}[✓] Generated $LOCK_FILE${NC}"
else
    echo -e "  ${YELLOW}[!] sha256sum not available, skipping lock${NC}"
fi
echo

# Summary
echo -e "${BOLD}════════════════════════════════════════════════${NC}"
if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}${BOLD}✓ PASSED${NC} - No critical issues found"
    echo -e "${GRAY}  Recommend: Add to Tier 2 (Trusted) trust level${NC}"
    exit 0
elif [ $ISSUES -lt 5 ]; then
    echo -e "${YELLOW}${BOLD}⚠ CAUTION${NC} - Minor issues found (score: -$ISSUES)"
    echo -e "${GRAY}  Recommend: Review and fix before deployment${NC}"
    exit 0
else
    echo -e "${RED}${BOLD}✗ FAILED${NC} - Critical issues found (score: -$ISSUES)"
    echo -e "${GRAY}  Recommend: Do NOT install. Tier 4 (Blocked) risk.${NC}"
    exit 1
fi
