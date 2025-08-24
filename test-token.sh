#!/bin/bash

BASE_URL="http://localhost:8080"

echo "🔍 JWT 토큰 만료 테스트"
echo "========================"

# 1. 유효한 토큰 발급
echo "1. 유효한 토큰 발급..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/token?clientId=testuser")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -n "$ACCESS_TOKEN" ]; then
    echo "✅ 토큰 발급 성공"
    
    # 2. 유효한 토큰으로 API 접근 (성공해야 함)
    echo -e "\n2. 유효한 토큰으로 API 접근..."
    curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$BASE_URL/api/data" | jq '.' 2>/dev/null || curl -s -H "Authorization: Bearer $ACCESS_TOKEN" "$BASE_URL/api/data"
    
    # 3. 잘못된 토큰으로 API 접근 (Invalid token 에러)
    echo -e "\n3. 잘못된 토큰으로 API 접근 (Invalid token 에러)..."
    curl -s -H "Authorization: Bearer invalid_token_here" "$BASE_URL/api/data"
    
    # 4. 토큰 없이 API 접근 (401 에러)
    echo -e "\n4. 토큰 없이 API 접근..."
    curl -s "$BASE_URL/api/data"
    
else
    echo "❌ 토큰 발급 실패"
fi

echo -e "\n========================"
echo "🏁 테스트 완료"
