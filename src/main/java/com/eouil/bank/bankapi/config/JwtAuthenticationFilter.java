package com.eouil.bank.bankapi.config;

import com.eouil.bank.bankapi.domains.User;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.services.RedisTokenService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import com.eouil.bank.bankapi.metrics.SecurityMetrics;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final RedisTokenService redisTokenService;
    private final JwtUtil jwtUtil;

    @Autowired
    private SecurityMetrics securityMetrics;

    public JwtAuthenticationFilter(UserRepository userRepository, RedisTokenService redisTokenService, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.redisTokenService = redisTokenService;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path.equals("/api/login")
                || path.equals("/api/join")
                || path.equals("/api/refresh")
                || path.equals("/api/logout")
                || path.startsWith("/api/mfa/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = null;

        // 1. Authorization 헤더에서 우선 탐색
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        // 2. 없으면 accessToken 쿠키에서 조회
        if (token == null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if ("accessToken".equals(cookie.getName())) {
                    token = cookie.getValue();
                    break;
                }
            }
        }

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (redisTokenService.isBlacklisted(token)) {
            securityMetrics.incrementInvalidJwt();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Blacklisted token");
            return;
        }

        try {
            String userId = jwtUtil.validateTokenAndGetUserId(token);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user.getUserId(), null, null
            );
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (JwtException | IllegalArgumentException e) {
            securityMetrics.incrementInvalidJwt();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
