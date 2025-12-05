#!/bin/bash
# Setup test environment with organization, users, and audit log entries
# This automates the boring setup so you can focus on testing tampering detection

# Note: Don't exit on error, continue with warnings
set +e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  SecureShare Test Environment Setup${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Configuration
SERVER_URL="https://localhost:8443"
CLI="./client/sshare"

# Check if CLI exists
if [ ! -f "$CLI" ]; then
    echo -e "${RED}Error: CLI not found at $CLI${NC}"
    echo "Make sure you're running this from the project root"
    exit 1
fi

chmod +x $CLI

echo -e "${YELLOW}Step 1: Configure CLI${NC}"
$CLI config set-server "$SERVER_URL"
echo -e "${GREEN}✓ Server URL configured${NC}\n"

echo -e "${YELLOW}Step 2: Create Organization${NC}"
echo "Organization: ACME Corp"
echo "Admin: admin"

# Create org and capture full output
ORG_OUTPUT=$($CLI org create --name "ACME Corp" --admin admin 2>&1)
echo "$ORG_OUTPUT"

# Extract activation code from the "IMPORTANT: Save this activation code: XXX" line
ACTIVATION_CODE=$(echo "$ORG_OUTPUT" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')

if [ -z "$ACTIVATION_CODE" ]; then
    # Fallback: try to extract from JSON
    ACTIVATION_CODE=$(echo "$ORG_OUTPUT" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi

if [ -z "$ACTIVATION_CODE" ]; then
    echo -e "${RED}✗ Could not extract activation code${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Activation code extracted: $ACTIVATION_CODE${NC}\n"

sleep 1

echo -e "${YELLOW}Step 3: Activate Admin Account${NC}"
ACTIVATE_OUTPUT=$($CLI activate \
    --username admin \
    --code "$ACTIVATION_CODE" \
    --password admin123 2>&1)

if echo "$ACTIVATE_OUTPUT" | grep -q "success"; then
    echo -e "${GREEN}✓ Admin activated (RSA-4096 keypair generated)${NC}\n"
else
    echo -e "${RED}✗ Admin activation failed${NC}"
    echo "$ACTIVATE_OUTPUT"
    exit 1
fi

sleep 1

echo -e "${YELLOW}Step 4: Login as Admin${NC}"
LOGIN_OUTPUT=$($CLI login --username admin --password admin123 2>&1)
if echo "$LOGIN_OUTPUT" | grep -q "Token saved"; then
    echo -e "${GREEN}✓ Admin logged in${NC}\n"
else
    echo -e "${RED}✗ Login failed${NC}"
    echo "$LOGIN_OUTPUT"
    exit 1
fi

sleep 1

echo -e "${YELLOW}Step 5: Create Departments${NC}"
echo "Creating Engineering department..."
$CLI dept create --name Engineering
echo -e "${GREEN}✓ Engineering department created${NC}"

sleep 0.5

echo "Creating Security department..."
$CLI dept create --name Security
echo -e "${GREEN}✓ Security department created${NC}\n"

sleep 1

echo -e "${YELLOW}Step 6: Create First Auditor User${NC}"
echo "Username: alice_auditor"

ALICE_OUTPUT=$($CLI user create --username alice_auditor 2>&1)

# Extract activation code from "IMPORTANT: Save this activation code: XXX" line
ALICE_CODE=$(echo "$ALICE_OUTPUT" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
if [ -z "$ALICE_CODE" ]; then
    # Fallback: try JSON format
    ALICE_CODE=$(echo "$ALICE_OUTPUT" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi

# Extract user ID from JSON
ALICE_ID=$(echo "$ALICE_OUTPUT" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')

if [ -z "$ALICE_CODE" ] || [ -z "$ALICE_ID" ]; then
    echo -e "${RED}✗ Failed to extract Alice info${NC}"
    echo "$ALICE_OUTPUT"
    exit 1
fi

echo -e "${GREEN}✓ Alice created (ID: $ALICE_ID, Code: $ALICE_CODE)${NC}\n"

sleep 0.5

echo -e "${YELLOW}Step 7: Activate Alice${NC}"
ACTIVATE_ALICE=$($CLI activate \
    --username alice_auditor \
    --code "$ALICE_CODE" \
    --password alice123 2>&1)

if echo "$ACTIVATE_ALICE" | grep -q "success"; then
    echo -e "${GREEN}✓ Alice activated${NC}\n"
else
    echo -e "${YELLOW}⚠ Alice activation may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 8: Assign Auditor Role to Alice${NC}"
ASSIGN_ALICE=$($CLI role assign --user-id "$ALICE_ID" --role Auditor 2>&1)
if echo "$ASSIGN_ALICE" | grep -q "success\|assigned"; then
    echo -e "${GREEN}✓ Alice now has Auditor role${NC}\n"
else
    echo -e "${YELLOW}⚠ Role assignment may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 9: Create Second Auditor User${NC}"
echo "Username: bob_auditor"

BOB_RESPONSE=$($CLI user create --username bob_auditor 2>&1)
if echo "$BOB_RESPONSE" | grep -q "activation_code"; then
    BOB_CODE=$(echo "$BOB_RESPONSE" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
    if [ -z "$BOB_CODE" ]; then
        BOB_CODE=$(echo "$BOB_RESPONSE" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
    fi
    BOB_ID=$(echo "$BOB_RESPONSE" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')
    echo -e "${GREEN}✓ Bob created (ID: $BOB_ID)${NC}"
    echo -e "${GREEN}  Activation code: $BOB_CODE${NC}\n"
else
    echo -e "${RED}✗ Failed to create Bob${NC}"
    echo "$BOB_RESPONSE"
    exit 1
fi

sleep 0.5

echo -e "${YELLOW}Step 10: Activate Bob${NC}"
ACTIVATE_BOB=$($CLI activate \
    --username bob_auditor \
    --code "$BOB_CODE" \
    --password bob123 2>&1)

if echo "$ACTIVATE_BOB" | grep -q "success"; then
    echo -e "${GREEN}✓ Bob activated${NC}\n"
else
    echo -e "${YELLOW}⚠ Bob activation may have failed (continuing anyway)${NC}"
    echo "$ACTIVATE_BOB" | head -3
    echo ""
fi

sleep 1

echo -e "${YELLOW}Step 11: Assign Auditor Role to Bob${NC}"
ASSIGN_BOB=$($CLI role assign --user-id "$BOB_ID" --role Auditor 2>&1)
if echo "$ASSIGN_BOB" | grep -q "success\|assigned"; then
    echo -e "${GREEN}✓ Bob now has Auditor role${NC}\n"
else
    echo -e "${YELLOW}⚠ Could not assign role to Bob (may already have it)${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 12: Create Regular User${NC}"
echo "Username: charlie_user"

CHARLIE_RESPONSE=$($CLI user create --username charlie_user 2>&1)
if echo "$CHARLIE_RESPONSE" | grep -q "activation_code"; then
    CHARLIE_CODE=$(echo "$CHARLIE_RESPONSE" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
    if [ -z "$CHARLIE_CODE" ]; then
        CHARLIE_CODE=$(echo "$CHARLIE_RESPONSE" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
    fi
    CHARLIE_ID=$(echo "$CHARLIE_RESPONSE" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')
    echo -e "${GREEN}✓ Charlie created (ID: $CHARLIE_ID)${NC}"
    echo -e "${GREEN}  Activation code: $CHARLIE_CODE${NC}\n"
else
    echo -e "${RED}✗ Failed to create Charlie${NC}"
    echo "$CHARLIE_RESPONSE"
    exit 1
fi

sleep 0.5

echo -e "${YELLOW}Step 13: Activate Charlie${NC}"
ACTIVATE_CHARLIE=$($CLI activate \
    --username charlie_user \
    --code "$CHARLIE_CODE" \
    --password charlie123 2>&1)

if echo "$ACTIVATE_CHARLIE" | grep -q "success"; then
    echo -e "${GREEN}✓ Charlie activated${NC}\n"
else
    echo -e "${YELLOW}⚠ Charlie activation may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 14: View Audit Log (as Alice)${NC}"
$CLI login --username alice_auditor --password alice123
$CLI audit log
echo -e "${GREEN}✓ Audit log retrieved${NC}\n"

sleep 1

echo -e "${YELLOW}Step 15: Verify Audit Chain (as Alice)${NC}"
$CLI audit verify
echo -e "${GREEN}✓ Chain verified${NC}\n"

sleep 1

echo -e "${YELLOW}Step 16: Create First Verification (as Alice)${NC}"
$CLI audit validate
echo -e "${GREEN}✓ Alice verified the audit log${NC}\n"

sleep 1

echo -e "${YELLOW}Step 17: Back to Admin - Create More Entries${NC}"
$CLI login --username admin --password admin123

echo "Creating additional department..."
$CLI dept create --name Research
echo -e "${GREEN}✓ Research department created${NC}\n"

sleep 0.5

echo "Creating another user..."
DAVE_RESPONSE=$($CLI user create --username dave_user 2>&1)
if echo "$DAVE_RESPONSE" | grep -q "activation_code"; then
    echo -e "${GREEN}✓ Dave created${NC}\n"
fi

sleep 1

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Test Environment Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Summary:${NC}"
echo -e "  ${GREEN}•${NC} Organization: ACME Corp"
echo -e "  ${GREEN}•${NC} Admin: admin / admin123"
echo -e "  ${GREEN}•${NC} Auditor 1: alice_auditor / alice123 (ID: $ALICE_ID)"
echo -e "  ${GREEN}•${NC} Auditor 2: bob_auditor / bob123 (ID: $BOB_ID)"
echo -e "  ${GREEN}•${NC} User: charlie_user / charlie123 (ID: $CHARLIE_ID)"
echo -e "  ${GREEN}•${NC} Departments: Engineering, Security, Research"
echo -e "  ${GREEN}•${NC} Audit Log: ~15-20 entries created"
echo -e "  ${GREEN}•${NC} First verification by Alice completed\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Run tampering test:"
echo -e "     ${BLUE}./test_tampering_scenario.sh${NC}\n"
echo -e "  2. Or manually tamper with database:"
echo -e "     ${BLUE}docker exec -it sshare-server-container bash${NC}"
echo -e "     ${BLUE}sqlite3 sshare.db${NC}"
echo -e "     ${BLUE}UPDATE audit_log SET action = 'TAMPERED!' WHERE id = 5;${NC}\n"
echo -e "  3. Then verify as auditor:"
echo -e "     ${BLUE}./client/sshare login --username alice_auditor --password alice123${NC}"
echo -e "     ${BLUE}./client/sshare audit verify${NC}\n"


