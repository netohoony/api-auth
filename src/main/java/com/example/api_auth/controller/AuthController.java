package com.example.api_auth.controller;

import com.example.api_auth.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private JwtService jwtService;
    
    @Value("${jwt.access-expiration}")
    private long accessTokenExpirationMs;
    
    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpirationMs;
    
    @Value("${allowed-clients}")
    private Map<String, List<String>> allowedClients;

    // Access Token + Refresh Token 발급
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> generateTokens(@RequestParam String clientId, HttpServletRequest request) {
        // 클라이언트 IP 주소 가져오기
        String clientIp = getClientIpAddress(request);
        
        // clientId와 IP 매칭 검증
        if (!isValidClientIdAndIp(clientId, clientIp)) {
            return ResponseEntity.status(403).body(Map.of(
                "error", "Invalid client ID or IP address",
                "message", "Client ID and IP address do not match"
            ));
        }
        
        Map<String, String> tokens = jwtService.generateTokenPair(clientId);

        Map<String, Object> response = new HashMap<>();
        response.put("access_token", tokens.get("access_token"));
        response.put("refresh_token", tokens.get("refresh_token"));
        response.put("token_type", "Bearer");
        response.put("access_token_expires_in", accessTokenExpirationMs / 1000); // 밀리초 → 초 변환
        response.put("refresh_token_expires_in", refreshTokenExpirationMs / 1000); // 밀리초 → 초 변환
        response.put("client_ip", clientIp);

        return ResponseEntity.ok(response);
    }

    // Refresh Token으로 새로운 Access Token 발급
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refreshAccessToken(@RequestBody Map<String, String> requestBody) {
        String refreshToken = requestBody.get("refreshToken");
        // Refresh Token 파라미터가 없는 경우
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Refresh token parameter is required",
                "message", "Please provide a refresh token parameter: /auth/refresh?refreshToken=your_refresh_token_here"
            ));
        }

        // Refresh Token 유효성 검사
        if (!jwtService.validateToken(refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
        }

        // Refresh Token이 만료되었는지 확인
        if (jwtService.isTokenExpired(refreshToken)) {
            return ResponseEntity.status(401).body(Map.of("error", "Refresh token expired"));
        }

        // Refresh Token에서 clientId 추출
        String clientId = jwtService.getClientIdFromToken(refreshToken);

        // 새로운 Access Token 생성
        String newAccessToken = jwtService.generateAccessToken(clientId);

        Map<String, Object> response = new HashMap<>();
        response.put("access_token", newAccessToken);
        response.put("token_type", "Bearer");
        response.put("expires_in", 600);

        return ResponseEntity.ok(response);
    }

    // 토큰 검증
    @GetMapping("/verify")
    public ResponseEntity<Map<String, Object>> verifyToken(@RequestParam(required = false) String token) {
        // 토큰 파라미터가 없는 경우
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Token parameter is required",
                "message", "Please provide a token parameter: /auth/verify?token=your_token_here"
            ));
        }

        boolean isValid = jwtService.validateToken(token);
        boolean isExpired = jwtService.isTokenExpired(token);
        String clientId = isValid ? jwtService.getClientIdFromToken(token) : null;
        long remainingTime = isValid ? jwtService.getRemainingTimeMs(token) : -1;

        Map<String, Object> response = new HashMap<>();
        response.put("valid", isValid);
        response.put("expired", isExpired);
        response.put("clientId", clientId);
        response.put("remaining_time_ms", remainingTime);
        response.put("remaining_time_minutes", remainingTime > 0 ? remainingTime / 60000 : 0);

        return ResponseEntity.ok(response);
    }

    // 토큰 정보 조회
    @GetMapping("/token-info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(@RequestParam(required = false) String token) {
        // 토큰 파라미터가 없는 경우
        if (token == null || token.trim().isEmpty()) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Token parameter is required",
                "message", "Please provide a token parameter: /auth/token-info?token=your_token_here"
            ));
        }

        try {
            // 토큰 유효성 검사
            if (!jwtService.validateToken(token)) {
                return ResponseEntity.status(400).body(Map.of(
                    "error", "Invalid token format",
                    "message", "The provided token is not a valid JWT token"
                ));
            }

            String clientId = jwtService.getClientIdFromToken(token);
            boolean isExpired = jwtService.isTokenExpired(token);
            long remainingTime = jwtService.getRemainingTimeMs(token);

            Map<String, Object> response = new HashMap<>();
            response.put("clientId", clientId);
            response.put("expired", isExpired);
            response.put("remaining_time_ms", remainingTime);
            response.put("remaining_time_minutes", remainingTime > 0 ? remainingTime / 60000 : 0);
            response.put("token_type", isExpired ? "Expired" : "Valid");
            response.put("token_length", token.length());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Token processing failed",
                "message", e.getMessage()
            ));
        }
    }
    
    // 클라이언트 IP 주소 가져오기
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
    
    // clientId와 IP 매칭 검증
    private boolean isValidClientIdAndIp(String clientId, String clientIp) {
        // 설정 파일에서 허용된 clientId와 IP 조합 확인
        if (allowedClients != null && allowedClients.containsKey(clientId)) {
            List<String> allowedIps = allowedClients.get(clientId);
            return allowedIps.contains(clientIp);
        }
        
        // 허용되지 않은 clientId
        return false;
    }
}