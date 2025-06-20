#!/bin/bash

# OAuth Server Test Script
# This script demonstrates the OAuth 2.0 flows

SERVER_URL="http://localhost:8080"
CLIENT_ID="test-client"
CLIENT_SECRET="test-secret"
REDIRECT_URI="http://localhost:8080/test/callback"

echo "=== OAuth Server Test Script ==="
echo "Server URL: $SERVER_URL"
echo

# Test 1: Health Check
echo "1. Testing health endpoint..."
curl -s "$SERVER_URL/health" | jq .
echo

# Test 2: Well-known configuration
echo "2. Testing well-known configuration..."
curl -s "$SERVER_URL/.well-known/oauth-authorization-server" | jq .
echo

# Test 3: Create a test user
echo "3. Creating test user..."
curl -s -X POST "$SERVER_URL/api/users" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "testpassword",
    "scopes": ["openid", "profile", "email", "read"]
  }' | jq .
echo

# Test 4: Client Credentials Flow
echo "4. Testing Client Credentials flow..."
CLIENT_CREDS_RESPONSE=$(curl -s -X POST "$SERVER_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&scope=read")

echo "Client Credentials Response:"
echo "$CLIENT_CREDS_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$CLIENT_CREDS_RESPONSE" | jq -r .access_token)
echo "Access Token: $ACCESS_TOKEN"
echo

# Test 5: Token Introspection
echo "5. Testing token introspection..."
curl -s -X POST "$SERVER_URL/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN" | jq .
echo

# Test 6: Authorization Code Flow (Manual steps)
echo "6. Authorization Code Flow (Manual):"
echo "   Step 1: Open this URL in your browser:"
echo "   $SERVER_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email&state=test123"
echo
echo "   Step 2: Login with credentials:"
echo "   Username: testuser"
echo "   Password: testpassword"
echo
echo "   Step 3: After authorization, you'll get a code. Use it to exchange for tokens:"
echo "   curl -X POST \"$SERVER_URL/token\" \\"
echo "     -H \"Content-Type: application/x-www-form-urlencoded\" \\"
echo "     -d \"grant_type=authorization_code&code=YOUR_CODE&redirect_uri=$REDIRECT_URI&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET\""
echo
echo "7. Testing PKCE Flow:"
echo "   Generate code verifier and challenge:"
echo "   CODE_VERIFIER=\$(openssl rand -base64 32 | tr -d \"=+/\" | cut -c1-43)"
echo "   CODE_CHALLENGE=\$(echo -n \$CODE_VERIFIER | openssl sha256 -binary | openssl base64 | tr -d \"=+/\" | cut -c1-43)"
echo "   Then use the authorization URL with PKCE:"
echo "   $SERVER_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid%20profile%20email&state=test123&code_challenge=\$CODE_CHALLENGE&code_challenge_method=S256"
echo "   And exchange with code_verifier instead of client_secret"
echo

echo "8. Testing Token Revocation:"
echo "   curl -X POST \"$SERVER_URL/revoke\" \\"
echo "     -H \"Content-Type: application/x-www-form-urlencoded\" \\"
echo "     -d \"token=\$ACCESS_TOKEN&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET\""
echo
echo "9. Testing Metrics:"
echo "   curl -s \"$SERVER_URL/metrics\" | jq ."
echo

echo "=== Test Complete ==="
echo "Note: Make sure PostgreSQL is running and the server is started with 'go run cmd/server/main.go'"
echo "New features added:"
echo "- ✅ PKCE (Proof Key for Code Exchange) support"
echo "- ✅ OpenID Connect ID tokens"  
echo "- ✅ Token revocation endpoint"
echo "- ✅ Comprehensive metrics and monitoring"
echo "- ✅ Production-ready Kubernetes manifests"