#!/bin/bash
# Complete tampering test scenario
# This script automates the entire test: setup → tamper → detect

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Audit Log Tampering Detection Test       ║${NC}"
echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}\n"

CLI="./client/sshare"

if [ ! -f "$CLI" ]; then
    echo -e "${RED}Error: CLI not found${NC}"
    exit 1
fi

chmod +x $CLI

# ============================================
# PHASE 1: Show Current State
# ============================================

echo -e "${BLUE}═══ PHASE 1: Current Audit Log State ═══${NC}\n"

echo -e "${YELLOW}Logging in as Alice (Auditor)...${NC}"
$CLI login --username alice_auditor --password alice123 > /dev/null 2>&1
echo -e "${GREEN}✓ Logged in${NC}\n"

echo -e "${YELLOW}Fetching audit log...${NC}"
AUDIT_LOG=$($CLI --as au audit log 2>&1)
echo "$AUDIT_LOG" | head -50
echo -e "${GREEN}✓ Current audit log retrieved${NC}\n"

echo -e "${YELLOW}Verifying chain integrity (should be VALID)...${NC}"
VERIFY_RESULT=$($CLI audit verify 2>&1)
echo "$VERIFY_RESULT"

if echo "$VERIFY_RESULT" | grep -q '"valid": true'; then
    echo -e "${GREEN}✓ Chain is currently VALID${NC}\n"
else
    echo -e "${RED}✗ Chain is already broken! Fix it first.${NC}"
    exit 1
fi

sleep 2

# ============================================
# PHASE 2: Choose Entry to Tamper
# ============================================

echo -e "${BLUE}═══ PHASE 2: Selecting Entry to Tamper ═══${NC}\n"

# Get entry count
echo -e "${YELLOW}Querying database for entries...${NC}"
ENTRY_COUNT=$(
    sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db "SELECT COUNT(*) FROM audit_log;" \
        2>/dev/null | tr -d '\r'
)

echo "Entries found: $ENTRY_COUNT"

if [ "$ENTRY_COUNT" -lt 3 ]; then
    echo -e "${RED}Not enough entries in audit log (need at least 3)${NC}"
    echo "Run ./setup_test_env.sh first"
    exit 1
fi

# Pick entry in the middle (not first or last)
TARGET_ENTRY=$((ENTRY_COUNT / 2))

echo -e "${GREEN}Total entries: $ENTRY_COUNT${NC}"
echo -e "${GREEN}Target entry for tampering: #$TARGET_ENTRY${NC}\n"

# Show original entry
echo -e "${YELLOW}Original Entry #$TARGET_ENTRY:${NC}"
ENTRY_INFO=$(sudo docker exec sshare-server-container \
    sqlite3 /app/sshare.db \
    "SELECT id || '|' || action || '|' || entryHash || '|' || previousHash FROM audit_log WHERE id = $TARGET_ENTRY;" \
    2>/dev/null | tr -d '\r')

if [ -z "$ENTRY_INFO" ]; then
    echo -e "${RED}Failed to retrieve entry #$TARGET_ENTRY${NC}"
    exit 1
fi

IFS='|' read -r id action hash prev <<< "$ENTRY_INFO"
echo -e "  ID: ${CYAN}$id${NC}"
echo -e "  Action: ${CYAN}$action${NC}"
echo -e "  entryHash: ${CYAN}${hash:0:30}...${NC}"
echo -e "  previousHash: ${CYAN}${prev:0:30}...${NC}"

sleep 2

# ============================================
# PHASE 3: Tamper with Entry
# ============================================

echo -e "\n${BLUE}═══ PHASE 3: Tampering with Audit Log ═══${NC}\n"

echo -e "${RED}⚠️  TAMPERING ALERT ⚠️${NC}"
echo -e "${RED}Simulating malicious actor modifying entry #$TARGET_ENTRY...${NC}\n"

# Get original action
ORIGINAL_ACTION=$(sudo docker exec sshare-server-container \
    sqlite3 /app/sshare.db \
    "SELECT action FROM audit_log WHERE id = $TARGET_ENTRY;" \
    2>/dev/null | tr -d '\r')

echo -e "${YELLOW}Original action:${NC}"
echo "  $ORIGINAL_ACTION"

# Tamper with the action field
TAMPERED_ACTION="TAMPERED_ENTRY: Malicious actor changed this at $(date '+%Y-%m-%d %H:%M:%S')"

sudo docker exec sshare-server-container \
    sqlite3 /app/sshare.db \
    "UPDATE audit_log SET action = '$TAMPERED_ACTION' WHERE id = $TARGET_ENTRY;" \
    2>/dev/null

echo -e "\n${RED}New action:${NC}"
echo "  $TAMPERED_ACTION"

echo -e "\n${RED}✗ Entry #$TARGET_ENTRY has been TAMPERED!${NC}"
echo -e "${YELLOW}Note: The entryHash still contains the hash of the ORIGINAL content.${NC}"
echo -e "${YELLOW}The verify_chain() function will recalculate the hash and detect the mismatch.${NC}\n"

sleep 3

# ============================================
# PHASE 4: Detection by Auditor
# ============================================

echo -e "${BLUE}═══ PHASE 4: Tampering Detection ═══${NC}\n"

echo -e "${YELLOW}Alice (Auditor) is now verifying the audit chain...${NC}\n"

sleep 1

# Don't exit on error here - we expect verification to fail
set +e
VERIFY_AFTER=$($CLI audit verify 2>&1)
VERIFY_EXIT_CODE=$?
set -e

echo "$VERIFY_AFTER"

if echo "$VERIFY_AFTER" | grep -q '"valid": false'; then
    echo -e "\n${GREEN}✓✓✓ TAMPERING DETECTED! ✓✓✓${NC}"
    echo -e "${GREEN}The audit system successfully identified the tampered entry!${NC}\n"

    # Extract details
    if echo "$VERIFY_AFTER" | grep -q "tampering_type"; then
        echo -e "${CYAN}Detection Details:${NC}"
        echo "$VERIFY_AFTER" | grep -E "(message|entry_id|expected_hash|stored_hash|tampering_type)" | \
            sed 's/^/  /'
    fi

    echo -e "\n${YELLOW}What happened:${NC}"
    echo "  1. Attacker changed the 'action' field of entry #$TARGET_ENTRY"
    echo "  2. The stored entryHash still contained the hash of the ORIGINAL content"
    echo "  3. verify_chain() recalculated the hash using the TAMPERED content"
    echo "  4. Calculated hash ≠ stored hash → TAMPERING DETECTED!"

    SUCCESS=true
else
    echo -e "\n${RED}✗ WARNING: Tampering NOT detected!${NC}"
    echo -e "${RED}This should not happen. Check verify_chain() implementation.${NC}"
    SUCCESS=false
fi

sleep 2

# ============================================
# PHASE 5: View Verification History
# ============================================

echo -e "\n${BLUE}═══ PHASE 5: Verification History ═══${NC}\n"

echo -e "${YELLOW}Viewing all audit verifications...${NC}"
$CLI audit verifications

sleep 2

# ============================================
# PHASE 6: Attempt to Create New Verification
# ============================================

echo -e "\n${BLUE}═══ PHASE 6: Attempting New Verification ═══${NC}\n"

echo -e "${YELLOW}Alice attempts to create a new verification...${NC}"
echo -e "${YELLOW}(This should FAIL because the chain is broken)${NC}\n"

VALIDATE_RESULT=$($CLI audit validate 2>&1 || true)
echo "$VALIDATE_RESULT"

if echo "$VALIDATE_RESULT" | grep -q -i "chain is broken\|tampered"; then
    echo -e "\n${GREEN}✓ System correctly PREVENTED verification of tampered chain!${NC}"
else
    echo -e "\n${YELLOW}Note: Verification might have been allowed (check implementation)${NC}"
fi

sleep 2

# ============================================
# PHASE 7: Restore Original Entry
# ============================================

echo -e "\n${BLUE}═══ PHASE 7: Restoring Original Entry ═══${NC}\n"

echo -e "${YELLOW}Would you like to restore the original entry? (y/n)${NC}"
read -r -p "> " RESTORE

if [[ "$RESTORE" =~ ^[Yy]$ ]]; then
    # Escape single quotes in the original action for SQL
    ESCAPED_ACTION=$(echo "$ORIGINAL_ACTION" | sed "s/'/''/g")

    sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "UPDATE audit_log SET action = '$ESCAPED_ACTION' WHERE id = $TARGET_ENTRY;" \
        2>/dev/null

    echo -e "${GREEN}✓ Entry #$TARGET_ENTRY restored${NC}\n"

    echo -e "${YELLOW}Verifying chain again...${NC}"
    set +e
    VERIFY_RESTORED=$($CLI audit verify 2>&1)
    set -e

    if echo "$VERIFY_RESTORED" | grep -q '"valid": true'; then
        echo -e "${GREEN}✓ Chain is now VALID again${NC}"
    else
        echo -e "${RED}✗ Chain still broken (unexpected)${NC}"
    fi

    SCENARIO_1_RESTORED=true
else
    echo -e "${YELLOW}Entry left in tampered state${NC}"
    SCENARIO_1_RESTORED=false
fi

sleep 2

# ============================================
# PHASE 8: Test Hash Tampering
# ============================================

echo -e "\n${BLUE}═══ PHASE 8: Testing Hash Tampering ═══${NC}\n"

echo -e "${YELLOW}Would you like to test hash tampering? (y/n)${NC}"
read -r -p "> " TEST_HASH

if [[ "$TEST_HASH" =~ ^[Yy]$ ]]; then
    # Pick a different entry to tamper (avoid the one from previous test)
    HASH_TARGET=$((TARGET_ENTRY + 1))
    if [ "$HASH_TARGET" -gt "$ENTRY_COUNT" ]; then
        HASH_TARGET=$((TARGET_ENTRY - 1))
    fi

    echo -e "\n${RED}⚠️  HASH TAMPERING ALERT ⚠️${NC}"
    echo -e "${RED}Modifying entryHash of entry #$HASH_TARGET...${NC}\n"

    # Get original hash
    ORIGINAL_HASH=$(sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "SELECT entryHash FROM audit_log WHERE id = $HASH_TARGET;" \
        2>/dev/null | tr -d '\r')

    echo -e "${YELLOW}Original hash:${NC} ${CYAN}$ORIGINAL_HASH${NC}"

    # Create fake hash (modify a few characters)
    FAKE_HASH="${ORIGINAL_HASH:0:50}FAKEHASH${ORIGINAL_HASH:58}"

    sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "UPDATE audit_log SET entryHash = '$FAKE_HASH' WHERE id = $HASH_TARGET;" \
        2>/dev/null

    echo -e "${RED}Tampered hash:${NC} ${CYAN}$FAKE_HASH${NC}"
    echo -e "\n${RED}✗ Entry #$HASH_TARGET hash has been TAMPERED!${NC}\n"

    sleep 2

    echo -e "${YELLOW}Alice verifies the chain...${NC}"
    set +e
    VERIFY_HASH=$($CLI audit verify 2>&1)
    set -e

    echo "$VERIFY_HASH"

    if echo "$VERIFY_HASH" | grep -q '"valid": false'; then
        echo -e "\n${GREEN}✓✓✓ HASH TAMPERING DETECTED! ✓✓✓${NC}"
        echo -e "${GREEN}The system detected that entryHash was modified!${NC}\n"

        echo -e "${YELLOW}What happened:${NC}"
        echo "  1. Attacker changed the 'entryHash' of entry #$HASH_TARGET"
        echo "  2. Entry #$((HASH_TARGET + 1))'s previousHash still points to the ORIGINAL hash"
        echo "  3. verify_chain() detected: previousHash ≠ current entryHash"
        echo "  4. Chain link broken → TAMPERING DETECTED!"

        HASH_TEST_SUCCESS=true
    else
        echo -e "\n${RED}✗ WARNING: Hash tampering NOT detected!${NC}"
        HASH_TEST_SUCCESS=false
    fi

    # Restore
    echo -e "\n${YELLOW}Restoring original hash...${NC}"
    sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "UPDATE audit_log SET entryHash = '$ORIGINAL_HASH' WHERE id = $HASH_TARGET;" \
        2>/dev/null
    echo -e "${GREEN}✓ Hash restored${NC}"
else
    HASH_TEST_SUCCESS="skipped"
fi

sleep 2

# ============================================
# PHASE 9: Test Entry Deletion
# ============================================

echo -e "\n${BLUE}═══ PHASE 9: Testing Entry Deletion ═══${NC}\n"

echo -e "${YELLOW}Would you like to test entry deletion? (y/n)${NC}"
read -r -p "> " TEST_DELETE

if [[ "$TEST_DELETE" =~ ^[Yy]$ ]]; then
    # Pick an entry in the middle to delete
    DELETE_TARGET=$TARGET_ENTRY

    echo -e "\n${RED}⚠️  DELETION ATTACK ALERT ⚠️${NC}"
    echo -e "${RED}Deleting entry #$DELETE_TARGET from audit log...${NC}\n"

    # Backup the entry before deleting
    DELETED_ENTRY=$(sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "SELECT id, timestamp, action, actor_id, previousHash, entryHash FROM audit_log WHERE id = $DELETE_TARGET;" \
        2>/dev/null | tr -d '\r')

    echo -e "${YELLOW}Entry to delete:${NC}"
    echo "  $DELETED_ENTRY"

    # Delete the entry
    sudo docker exec sshare-server-container \
        sqlite3 /app/sshare.db \
        "DELETE FROM audit_log WHERE id = $DELETE_TARGET;" \
        2>/dev/null

    echo -e "\n${RED}✗ Entry #$DELETE_TARGET has been DELETED!${NC}\n"

    sleep 2

    echo -e "${YELLOW}Alice verifies the chain...${NC}"
    set +e
    VERIFY_DELETE=$($CLI audit verify 2>&1)
    set -e

    echo "$VERIFY_DELETE"

    if echo "$VERIFY_DELETE" | grep -q '"valid": false'; then
        echo -e "\n${GREEN}✓✓✓ DELETION DETECTED! ✓✓✓${NC}"
        echo -e "${GREEN}The system detected that an entry was removed!${NC}\n"

        echo -e "${YELLOW}What happened:${NC}"
        echo "  1. Attacker deleted entry #$DELETE_TARGET"
        echo "  2. Entry #$((DELETE_TARGET + 1))'s previousHash points to the DELETED entry"
        echo "  3. verify_chain() cannot find the entry that previousHash references"
        echo "  4. Chain break detected → DELETION ATTACK PREVENTED!"

        DELETE_TEST_SUCCESS=true
    else
        echo -e "\n${RED}✗ WARNING: Deletion NOT detected!${NC}"
        DELETE_TEST_SUCCESS=false
    fi

    # Note: We won't restore deleted entries (complex to restore with proper structure)
    echo -e "\n${YELLOW}Note: Deleted entry cannot be easily restored via script.${NC}"
    echo -e "${YELLOW}Run ./setup_test_env.sh to create a fresh environment.${NC}"
else
    DELETE_TEST_SUCCESS="skipped"
fi

# ============================================
# Summary
# ============================================

echo -e "\n${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║           Test Summary                     ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}\n"

echo -e "${YELLOW}Tests Performed:${NC}"
echo ""

# Scenario 1: Content Tampering
echo -e "${BLUE}1. Content Tampering (Entry #$TARGET_ENTRY)${NC}"
if [ "$SUCCESS" = true ]; then
    echo -e "   ${GREEN}✓ PASSED${NC} - Modified action field detected"
else
    echo -e "   ${RED}✗ FAILED${NC} - Tampering not detected"
fi

# Scenario 2: Hash Tampering
echo -e "${BLUE}2. Hash Tampering${NC}"
if [ "$HASH_TEST_SUCCESS" = true ]; then
    echo -e "   ${GREEN}✓ PASSED${NC} - Modified entryHash detected"
elif [ "$HASH_TEST_SUCCESS" = false ]; then
    echo -e "   ${RED}✗ FAILED${NC} - Hash tampering not detected"
else
    echo -e "   ${YELLOW}⊘ SKIPPED${NC} - Test not performed"
fi

# Scenario 3: Entry Deletion
echo -e "${BLUE}3. Entry Deletion${NC}"
if [ "$DELETE_TEST_SUCCESS" = true ]; then
    echo -e "   ${GREEN}✓ PASSED${NC} - Deleted entry detected"
elif [ "$DELETE_TEST_SUCCESS" = false ]; then
    echo -e "   ${RED}✗ FAILED${NC} - Deletion not detected"
else
    echo -e "   ${YELLOW}⊘ SKIPPED${NC} - Test not performed"
fi

echo ""

# Overall result
OVERALL_PASS=true
if [ "$SUCCESS" != true ]; then OVERALL_PASS=false; fi
if [ "$HASH_TEST_SUCCESS" = false ]; then OVERALL_PASS=false; fi
if [ "$DELETE_TEST_SUCCESS" = false ]; then OVERALL_PASS=false; fi

if [ "$OVERALL_PASS" = true ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ ALL TESTS PASSED!                 ║${NC}"
    echo -e "${GREEN}║  Audit system integrity verified     ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
else
    echo -e "${RED}╔═══════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ SOME TESTS FAILED                  ║${NC}"
    echo -e "${RED}║  Review verify_chain() implementation ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════╝${NC}"
fi

echo -e "${CYAN}Test completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}"

echo -e "${CYAN}Test completed at $(date '+%Y-%m-%d %H:%M:%S')${NC}"
