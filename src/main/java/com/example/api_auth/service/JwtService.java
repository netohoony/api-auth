package com.example.api_auth.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {

    private final SecretKey secretKey;
    private final long accessTokenExpirationMs;
    private final long refreshTokenExpirationMs;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-expiration:600000}") long accessTokenExpirationMs,
                      @Value("${jwt.refresh-expiration:2592000000}") long refreshTokenExpirationMs) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessTokenExpirationMs = accessTokenExpirationMs; // 1시간
        this.refreshTokenExpirationMs = refreshTokenExpirationMs; // 30일
    }

    // Access Token 생성
    public String generateAccessToken(String clientId) {
        return Jwts.builder()
                .setSubject(clientId)
                .claim("token_type", "access")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenExpirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Refresh Token 생성
    public String generateRefreshToken(String clientId) {
        return Jwts.builder()
                .setSubject(clientId)
                .claim("token_type", "refresh")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // Access Token + Refresh Token 쌍으로 생성
    public Map<String, String> generateTokenPair(String clientId) {
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", generateAccessToken(clientId));
        tokens.put("refresh_token", generateRefreshToken(clientId));
        return tokens;
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            // 토큰 만료는 별도 처리 Filter에서 처리
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // 토큰에서 클라이언트 ID 추출 (만료된 토큰도 처리)
    public String getClientIdFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            // 만료된 토큰에서도 clientId 추출 가능
            return e.getClaims().getSubject();
        } catch (Exception e) {
            throw new RuntimeException("Invalid token: getClientIdFromToken");
        }
    }

    // 토큰 만료 여부 확인
    public boolean isTokenExpired(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Invalid token expired");
        }
    }

    // 토큰 남은 시간 확인 (밀리초)
    public long getRemainingTimeMs(String token) {
        try {
            Date expiration = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getExpiration();
            return expiration.getTime() - System.currentTimeMillis();
        } catch (ExpiredJwtException e) {
            return -1; // 이미 만료됨
        } catch (Exception e) {
            throw new RuntimeException("Invalid token: getRemainingTimeMs");
        }
    }

    // 토큰 타입 추출
    public String getTokenType(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
            return claims.get("token_type", String.class);
        } catch (Exception e) {
            return null;
        }
    }
}