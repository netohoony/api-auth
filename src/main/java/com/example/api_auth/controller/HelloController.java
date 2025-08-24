package com.example.api_auth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class HelloController {

    @GetMapping("/")
    public Map<String, Object> hello(){
        return Map.of(
            "message", "API Auth System is running!",
            "status", "active",
            "endpoints", Map.of(
                "auth", "/auth/** - 인증 관련 API (토큰 발급, 갱신, 검증)",
                "api", "/api/** - 보호된 API (JWT 토큰 필요)",
                "docs", "README.md 파일을 참조하세요"
            ),
            "timestamp", System.currentTimeMillis()
        );
    }
}
