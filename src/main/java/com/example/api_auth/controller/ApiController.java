package com.example.api_auth.controller;

import com.example.api_auth.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private JwtService jwtService;

    private ResponseEntity<Map<String, Object>> validateToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(Map.of("error", "Token required"));
        }

        String token = authHeader.substring(7);

        if (!jwtService.validateToken(token)) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
        }

        if (jwtService.isTokenExpired(token)) {
            return ResponseEntity.status(401).body(Map.of(
                    "error", "Token expired",
                    "message", "Please refresh your token using the refresh token"
            ));
        }

        return null; // 유효한 토큰
    }

    @GetMapping("/data")
    public ResponseEntity<Map<String, Object>> getData() {
        // SecurityContext에서 인증된 사용자 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String clientId = authentication.getName();

        Map<String, Object> data = Map.of(
                "clientId", clientId,
                "message", "Hello from A system!",
                "timestamp", System.currentTimeMillis(),
                "data", "Some important data from A system"
        );

        return ResponseEntity.ok(data);
    }

    @PostMapping("/process")
    public ResponseEntity<Map<String, Object>> processData(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody Map<String, Object> requestData) {

        ResponseEntity<Map<String, Object>> validationError = validateToken(authHeader);
        if (validationError != null) {
            return validationError;
        }

        String token = authHeader.substring(7);
        String clientId = jwtService.getClientIdFromToken(token);

        Map<String, Object> response = Map.of(
                "clientId", clientId,
                "status", "processed",
                "receivedData", requestData,
                "result", "success"
        );

        return ResponseEntity.ok(response);
    }
}