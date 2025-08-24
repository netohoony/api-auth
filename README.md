# API Auth System

JWT 토큰 기반 인증을 제공하는 Spring Boot API 서버입니다.

## 주요 기능

- JWT Access Token 및 Refresh Token 발급
- 토큰 기반 API 인증
- 토큰 유효성 검증 및 갱신

## API 엔드포인트

### 인증 API (인증 불필요)

#### 1. 토큰 발급
```http
POST /auth/token?clientId={clientId}
```
**응답:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "access_token_expires_in": 3600,
  "refresh_token_expires_in": 2592000
}
```

#### 2. 토큰 갱신
```http
POST /auth/refresh?refreshToken={refreshToken}
```

#### 3. 토큰 검증
```http
GET /auth/verify?token={token}
```

#### 4. 토큰 정보 조회
```http
GET /auth/token-info?token={token}
```

### 보호된 API (JWT 토큰 필요)

#### 1. 데이터 조회
```http
GET /api/data
Authorization: Bearer {access_token}
```

#### 2. 데이터 처리
```http
POST /api/process
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "data": "example data"
}
```

## 사용법

### 1. 프로젝트 실행
```bash
./gradlew bootRun
```

### 2. 토큰 발급
```bash
curl -X POST "http://localhost:8080/auth/token?clientId=testuser"
```

### 3. 보호된 API 접근
```bash
curl -H "Authorization: Bearer {access_token}" \
     http://localhost:8080/api/data
```

## 설정

- **JWT Secret**: `application.yaml`의 `jwt.secret`에서 설정
- **Access Token 만료시간**: 1시간 (3600000ms)
- **Refresh Token 만료시간**: 30일 (2592000000ms)

## 보안

- CSRF 비활성화
- Stateless 세션 관리
- JWT 기반 인증
- `/auth/**` 경로는 인증 없이 접근 가능
- 나머지 API는 JWT 토큰 필요
