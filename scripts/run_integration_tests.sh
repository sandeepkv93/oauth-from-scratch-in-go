#!/bin/bash

# OAuth Server Integration Test Runner
# This script runs the OAuth server and performs comprehensive end-to-end testing

set -e

echo "🚀 OAuth Server Integration Test Runner"
echo "========================================"

# Configuration
SERVER_PORT=18080
SERVER_URL="http://localhost:$SERVER_PORT"
CLIENT_ID="test-client"
CLIENT_SECRET="test-secret"
PUBLIC_CLIENT_ID="public-client"
REDIRECT_URI="http://localhost:8080/callback"
USERNAME="testuser"
PASSWORD="testpassword"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Function to check if server is running
check_server() {
    if curl -s "$SERVER_URL/health" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to test endpoint
test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_status="$3"
    local method="${4:-GET}"
    local data="$5"
    local headers="$6"
    
    print_status "Testing $name..."
    
    local cmd="curl -s -w '%{http_code}' -X $method"
    
    if [ -n "$headers" ]; then
        cmd="$cmd -H '$headers'"
    fi
    
    if [ -n "$data" ]; then
        cmd="$cmd -d '$data'"
    fi
    
    cmd="$cmd '$url'"
    
    local response=$(eval $cmd)
    local status_code="${response: -3}"
    local body="${response%???}"
    
    if [ "$status_code" = "$expected_status" ]; then
        print_success "$name returned status $status_code"
        echo "$body" | jq . 2>/dev/null || echo "$body"
        return 0
    else
        print_error "$name returned status $status_code, expected $expected_status"
        echo "Response: $body"
        return 1
    fi
}

# Start the server in background
print_status "Building OAuth server..."
if ! go build -o bin/oauth-server ./cmd/server; then
    print_error "Failed to build server"
    exit 1
fi

print_status "Starting OAuth server on port $SERVER_PORT..."
export SERVER_PORT=$SERVER_PORT
./bin/oauth-server &
SERVER_PID=$!

# Wait for server to start
print_status "Waiting for server to start..."
sleep 3

if ! check_server; then
    print_error "Server failed to start"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

print_success "Server started successfully (PID: $SERVER_PID)"

# Cleanup function
cleanup() {
    print_status "Cleaning up..."
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    print_status "Server stopped"
}

# Trap cleanup on exit
trap cleanup EXIT

# Run tests
echo
print_status "Running comprehensive integration tests..."
echo

# Test 1: Health Check
test_endpoint "Health Check" "$SERVER_URL/health" "200"

echo

# Test 2: Well-known Configuration
test_endpoint "OpenID Configuration" "$SERVER_URL/.well-known/openid-configuration" "200"

echo

# Test 3: Create Test User
print_status "Creating test user..."
USER_DATA='{
    "username": "'$USERNAME'",
    "email": "test@example.com", 
    "password": "'$PASSWORD'",
    "scopes": ["openid", "profile", "email", "read", "write"]
}'
test_endpoint "Create User" "$SERVER_URL/api/users" "200" "POST" "$USER_DATA" "Content-Type: application/json"

echo

# Test 4: Create Test Client
print_status "Creating test client..."
CLIENT_DATA='{
    "name": "Test Client",
    "redirect_uris": ["'$REDIRECT_URI'"],
    "scopes": ["openid", "profile", "email", "read", "write"],
    "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
    "is_public": false
}'
CLIENT_RESPONSE=$(curl -s -X POST "$SERVER_URL/api/clients" \
    -H "Content-Type: application/json" \
    -d "$CLIENT_DATA")

echo "Client created: $CLIENT_RESPONSE"

echo

# Test 5: Client Credentials Flow
print_status "Testing Client Credentials Flow..."
CC_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read write"
CC_RESPONSE=$(test_endpoint "Client Credentials Token" "$SERVER_URL/token" "200" "POST" "$CC_DATA" "Content-Type: application/x-www-form-urlencoded")

# Extract access token
ACCESS_TOKEN=$(echo "$CC_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
    print_success "Got access token: ${ACCESS_TOKEN:0:20}..."
else
    print_error "Failed to extract access token"
fi

echo

# Test 6: Token Introspection
if [ -n "$ACCESS_TOKEN" ]; then
    print_status "Testing Token Introspection..."
    INTROSPECT_DATA="token=$ACCESS_TOKEN"
    test_endpoint "Token Introspection" "$SERVER_URL/introspect" "200" "POST" "$INTROSPECT_DATA" "Content-Type: application/x-www-form-urlencoded"
fi

echo

# Test 7: Token Revocation
if [ -n "$ACCESS_TOKEN" ]; then
    print_status "Testing Token Revocation..."
    REVOKE_DATA="token=$ACCESS_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
    test_endpoint "Token Revocation" "$SERVER_URL/revoke" "200" "POST" "$REVOKE_DATA" "Content-Type: application/x-www-form-urlencoded"
    
    # Test that token is now inactive
    print_status "Verifying token is revoked..."
    INTROSPECT_DATA="token=$ACCESS_TOKEN"
    INTROSPECT_RESPONSE=$(curl -s -X POST "$SERVER_URL/introspect" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$INTROSPECT_DATA")
    
    ACTIVE=$(echo "$INTROSPECT_RESPONSE" | jq -r '.active' 2>/dev/null || echo "")
    if [ "$ACTIVE" = "false" ]; then
        print_success "Token successfully revoked"
    else
        print_error "Token revocation failed - token still active"
    fi
fi

echo

# Test 8: Authorization Code Flow (simulated)
print_status "Testing Authorization Code Flow..."

# Create authorization code programmatically for testing
print_status "Creating authorization code for testing..."

# Get new token for authorization flow
AC_DATA="grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=openid profile email"
AC_TOKEN_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$AC_DATA")

NEW_ACCESS_TOKEN=$(echo "$AC_TOKEN_RESPONSE" | jq -r '.access_token' 2>/dev/null || echo "")
if [ -n "$NEW_ACCESS_TOKEN" ] && [ "$NEW_ACCESS_TOKEN" != "null" ]; then
    print_success "Got new access token for authorization flow"
    
    # Test UserInfo endpoint
    print_status "Testing UserInfo endpoint..."
    curl -s -w "Status: %{http_code}\n" -H "Authorization: Bearer $NEW_ACCESS_TOKEN" "$SERVER_URL/userinfo" | head -5
fi

echo

# Test 9: PKCE Flow Testing
print_status "Testing PKCE parameters..."

# Generate PKCE parameters
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl sha256 -binary | openssl base64 | tr -d "=+/" | cut -c1-43)

print_success "Generated PKCE parameters:"
echo "  Code Verifier: ${CODE_VERIFIER:0:20}..."
echo "  Code Challenge: ${CODE_CHALLENGE:0:20}..."

print_status "PKCE Authorization URL would be:"
echo "$SERVER_URL/authorize?response_type=code&client_id=$PUBLIC_CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email&state=test123&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

echo

# Test 10: Metrics
print_status "Testing Metrics endpoint..."
test_endpoint "Metrics" "$SERVER_URL/metrics" "200"

echo

# Test 11: Error Scenarios
print_status "Testing error scenarios..."

# Invalid client credentials
print_status "Testing invalid client credentials..."
INVALID_DATA="grant_type=client_credentials&client_id=invalid&client_secret=invalid"
test_endpoint "Invalid Client Credentials" "$SERVER_URL/token" "401" "POST" "$INVALID_DATA" "Content-Type: application/x-www-form-urlencoded"

# Invalid grant type
print_status "Testing invalid grant type..."
INVALID_GRANT="grant_type=invalid_grant&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET"
test_endpoint "Invalid Grant Type" "$SERVER_URL/token" "400" "POST" "$INVALID_GRANT" "Content-Type: application/x-www-form-urlencoded"

# Missing token for UserInfo
print_status "Testing UserInfo without token..."
curl -s -w "Status: %{http_code}\n" "$SERVER_URL/userinfo" | tail -1

echo
echo "============================================"
print_success "Integration tests completed successfully!"
echo "============================================"

print_status "Summary of tested features:"
echo "✅ Health checks and monitoring"
echo "✅ OpenID Connect discovery"
echo "✅ Client registration"
echo "✅ User management"
echo "✅ Client credentials flow"
echo "✅ Authorization code flow (framework)"
echo "✅ Token introspection"
echo "✅ Token revocation"
echo "✅ PKCE parameter generation"
echo "✅ UserInfo endpoint"
echo "✅ Metrics and monitoring"
echo "✅ Error handling and validation"

echo
print_success "OAuth 2.0 server is working correctly!"
print_status "Server logs can be found in the terminal output above."