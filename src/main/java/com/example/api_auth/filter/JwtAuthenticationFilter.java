package com.example.api_auth.filter;

import com.example.api_auth.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtService jwtService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        
        // /api/** 경로에 대해서만 JWT 토큰 검증
        if (!requestURI.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");

        // Authorization 헤더가 없으면 에러 응답
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            sendErrorResponse(response, "Authorization header required", 401);
            return;
        }

        try {
            String token = authHeader.substring(7);

            // 토큰 유효성 검사
            if (!jwtService.validateToken(token)) {
                sendErrorResponse(response, "Invalid token: jwtService", 401);
                return;
            }

            // 토큰 만료 검사
            if (jwtService.isTokenExpired(token)) {
                sendErrorResponse(response, "Token expired", 401);
                return;
            }

       

            // Access Token인지 확인토큰 타입으로 구분
            String tokenType = jwtService.getTokenType(token);
            if (!"access".equals(tokenType)) {
                sendErrorResponse(response, "Access token required, refresh token not allowed", 401);
                return;
            }

            String clientId = jwtService.getClientIdFromToken(token);

            // 인증 객체 생성 (자격 증명 없이 clientId만 사용)
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(clientId, null, null);

            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // 인증 성공시 다음 필터로 진행
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            // 인증 실패시 컨텍스트 클리어
            SecurityContextHolder.clearContext();
            sendErrorResponse(response, "Authentication failed", 401);
            return;
        }
    }

    private void sendErrorResponse(HttpServletResponse response, String message, int status) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", message);
        errorResponse.put("status", status);
        errorResponse.put("timestamp", System.currentTimeMillis());

        String jsonResponse = objectMapper.writeValueAsString(errorResponse);
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
}