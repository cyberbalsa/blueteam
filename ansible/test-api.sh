#!/bin/bash
# Test script for the php-crud-api deployment
# Usage: ./test-api.sh [host_ip]

HOST=${1:-"100.65.3.71"}  # Default to first debian VM IP
BASE_URL="http://${HOST}"

echo "Testing php-crud-api deployment on ${HOST}"
echo "========================================"

# Test 1: Basic connectivity
echo -e "\n1. Testing basic connectivity..."
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" "${BASE_URL}/test.php" || echo "Failed to connect"

# Test 2: Test endpoint
echo -e "\n2. Testing test endpoint..."
curl -s "${BASE_URL}/test.php" | python3 -m json.tool 2>/dev/null || echo "Invalid JSON response"

# Test 3: API records endpoint
echo -e "\n3. Testing API records endpoint..."
curl -s "${BASE_URL}/records" | head -c 200
echo -e "\n..."

# Test 4: OpenAPI documentation
echo -e "\n4. Testing OpenAPI documentation..."
curl -s "${BASE_URL}/openapi" | head -c 200
echo -e "\n..."

# Test 5: Check nginx lua logging
echo -e "\n5. Checking if lua module is working (check nginx error logs on server)..."
curl -s "${BASE_URL}/" > /dev/null

# Test 6: Security headers check
echo -e "\n6. Checking security headers..."
curl -s -I "${BASE_URL}/" | grep -E "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options)"

echo -e "\n\nTest completed. Check server logs for lua access logging."
echo "For detailed API exploration, visit: ${BASE_URL}/openapi"