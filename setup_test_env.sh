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

echo -e "${YELLOW}Step 1: Configure CLI & Clean State${NC}"
$CLI config set-server "$SERVER_URL"
# Clean previous acting roles to avoid "User does not have Auditor" errors
$CLI config clear-role > /dev/null 2>&1
$CLI config clear-clearance > /dev/null 2>&1
echo -e "${GREEN}✓ Server URL configured and state cleaned${NC}\n"

echo -e "${YELLOW}Step 2: Create Organization${NC}"
echo "Organization: ACME Corp"
echo "Admin: admin"

# Create org and capture full output
ORG_OUTPUT=$($CLI org create --name "ACME Corp" --admin admin 2>&1)
echo "$ORG_OUTPUT"

# Extract activation code
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
# Use --as ad to explicitly act as Administrator
$CLI --as ad dept create --name Engineering
echo -e "${GREEN}✓ Engineering department created${NC}"

sleep 0.5

echo "Creating Security department..."
$CLI --as ad dept create --name Security
echo -e "${GREEN}✓ Security department created${NC}\n"

sleep 1

echo -e "${YELLOW}Step 6: Create Security Officer (TheSecurity)${NC}"
echo "Username: TheSecurity"

ts_output=$($CLI --as ad user create --username TheSecurity 2>&1)

# Extract activation code
ts_code=$(echo "$ts_output" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
if [ -z "$ts_code" ]; then
    ts_code=$(echo "$ts_output" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi
ts_id=$(echo "$ts_output" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')

if [ -z "$ts_code" ] || [ -z "$ts_id" ]; then
    echo -e "${RED}✗ Failed to extract TheSecurity info${NC}"
    echo "$ts_output"
    exit 1
fi

echo -e "${GREEN}✓ TheSecurity created (ID: $ts_id)${NC}\n"

sleep 0.5

echo -e "${YELLOW}Step 7: Activate TheSecurity${NC}"
ACTIVATE_TS=$($CLI activate \
    --username TheSecurity \
    --code "$ts_code" \
    --password 123 2>&1)

if echo "$ACTIVATE_TS" | grep -q "success"; then
    echo -e "${GREEN}✓ TheSecurity activated (Password: 123)${NC}\n"
else
    echo -e "${YELLOW}⚠ TheSecurity activation may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 8: Assign Role to TheSecurity${NC}"
# Assign 'so' (Security Officer)
ASSIGN_TS=$($CLI --as ad role assign --user-id "$ts_id" --role so 2>&1)
if echo "$ASSIGN_TS" | grep -q "success\|assigned"; then
    echo -e "${GREEN}✓ TheSecurity now has Security Officer role${NC}\n"
else
    echo -e "${YELLOW}⚠ Role assignment may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 9: Create Auditor (bob_auditor)${NC}"
echo "Username: bob_auditor"

BOB_RESPONSE=$($CLI --as ad user create --username bob_auditor 2>&1)
BOB_CODE=$(echo "$BOB_RESPONSE" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
if [ -z "$BOB_CODE" ]; then
    BOB_CODE=$(echo "$BOB_RESPONSE" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi
BOB_ID=$(echo "$BOB_RESPONSE" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')

echo -e "${GREEN}✓ Bob created (ID: $BOB_ID)${NC}\n"

sleep 0.5

echo -e "${YELLOW}Step 10: Activate Bob${NC}"
ACTIVATE_BOB=$($CLI activate \
    --username bob_auditor \
    --code "$BOB_CODE" \
    --password bob123 2>&1)

if echo "$ACTIVATE_BOB" | grep -q "success"; then
    echo -e "${GREEN}✓ Bob activated${NC}\n"
else
    echo -e "${YELLOW}⚠ Bob activation may have failed${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 11: Create Auditor (alice_auditor)${NC}"
echo "Username: alice_auditor"

ALICE_OUTPUT=$($CLI --as ad user create --username alice_auditor 2>&1)
ALICE_CODE=$(echo "$ALICE_OUTPUT" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
if [ -z "$ALICE_CODE" ]; then
    ALICE_CODE=$(echo "$ALICE_OUTPUT" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi
ALICE_ID=$(echo "$ALICE_OUTPUT" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')
echo -e "${GREEN}✓ Alice created (ID: $ALICE_ID)${NC}\n"

sleep 0.5

echo -e "${YELLOW}Step 12: Activate Alice${NC}"
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

echo -e "${YELLOW}Step 13: Create Regular User (charlie_user)${NC}"
CHARLIE_RESPONSE=$($CLI --as ad user create --username charlie_user 2>&1)
CHARLIE_CODE=$(echo "$CHARLIE_RESPONSE" | grep "IMPORTANT:" | sed -n 's/.*activation code: \([A-Za-z0-9_-]*\).*/\1/p')
if [ -z "$CHARLIE_CODE" ]; then
    CHARLIE_CODE=$(echo "$CHARLIE_RESPONSE" | grep '"activation_code"' | sed -n 's/.*"activation_code": *"\([^"]*\)".*/\1/p')
fi
CHARLIE_ID=$(echo "$CHARLIE_RESPONSE" | grep '"user_id"' | sed -n 's/.*"user_id": *\([0-9]*\).*/\1/p')

echo -e "${GREEN}✓ Charlie created (ID: $CHARLIE_ID)${NC}\n"

sleep 0.5

echo -e "${YELLOW}Step 14: Activate Charlie${NC}"
$CLI activate --username charlie_user --code "$CHARLIE_CODE" --password charlie123 > /dev/null
echo -e "${GREEN}✓ Charlie activated${NC}\n"

sleep 1

echo -e "${YELLOW}Step 15: Login as TheSecurity (SO)${NC}"
$CLI login --username TheSecurity --password 123
# Clean roles from config just in case
$CLI config clear-role > /dev/null 2>&1

echo -e "${YELLOW}Step 16: Assign Auditor Role to Alice & Bob (as SO)${NC}"
# SO can assign roles.
ASSIGN_ALICE=$($CLI --as so role assign --user-id "$ALICE_ID" --role Auditor 2>&1)
ASSIGN_BOB=$($CLI --as so role assign --user-id "$BOB_ID" --role Auditor 2>&1)

if echo "$ASSIGN_ALICE" | grep -q "success\|assigned"; then
    echo -e "${GREEN}✓ Auditor role assigned to Alice${NC}"
fi
if echo "$ASSIGN_BOB" | grep -q "success\|assigned"; then
    echo -e "${GREEN}✓ Auditor role assigned to Bob${NC}\n"
fi

sleep 1

echo -e "${YELLOW}Step 17: Login as Alice (Auditor)${NC}"
# Use Alice for verification
$CLI login --username alice_auditor --password alice123
$CLI config clear-role > /dev/null 2>&1

echo -e "${YELLOW}Step 18: View Audit Log (as Alice)${NC}"
$CLI --as au audit log
echo -e "${GREEN}✓ Audit log retrieved${NC}\n"

sleep 1

echo -e "${YELLOW}Step 19: Verify Audit Chain (as Alice)${NC}"
$CLI --as au audit verify
echo -e "${GREEN}✓ Chain verified${NC}\n"

sleep 1

echo -e "${YELLOW}Step 20: Create First Verification (as Alice)${NC}"
$CLI --as au audit validate
echo -e "${GREEN}✓ Alice verified the audit log${NC}\n"

sleep 1

echo -e "${YELLOW}Step 21: Back to Admin${NC}"
$CLI login --username admin --password admin123
$CLI config clear-role > /dev/null 2>&1

echo "Creating additional department..."
$CLI --as ad dept create --name Research
echo -e "${GREEN}✓ Research department created${NC}\n"

sleep 0.5

echo "Creating another user..."
$CLI --as ad user create --username dave_user > /dev/null 2>&1
echo -e "${GREEN}✓ Dave created${NC}\n"

sleep 1

echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}✓ Test Environment Setup Complete!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Summary:${NC}"
echo -e "  ${GREEN}•${NC} Organization: ACME Corp"
echo -e "  ${GREEN}•${NC} Admin: admin / admin123"
echo -e "  ${GREEN}•${NC} Security Officer: TheSecurity / 123 (ID: $ts_id)"
echo -e "  ${GREEN}•${NC} Auditor 1: alice_auditor / alice123 (ID: $ALICE_ID)"
echo -e "  ${GREEN}•${NC} Auditor 2: bob_auditor / bob123 (ID: $BOB_ID)"
echo -e "  ${GREEN}•${NC} User: charlie_user / charlie123 (ID: $CHARLIE_ID)"
echo -e "  ${GREEN}•${NC} Departments: Engineering, Security, Research"
echo -e "  ${GREEN}•${NC} First verification by Alice completed\n"

echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Run tampering test:"
echo -e "     ${BLUE}./test_tampering_scenario.sh${NC}\n"
echo -e "  2. Or verify manually:"
echo -e "     ${BLUE}./client/sshare login --username alice_auditor --password alice123${NC}"
echo -e "     ${BLUE}./client/sshare audit verify${NC}\n"
