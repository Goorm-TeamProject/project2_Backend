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

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;


@Component
@Slf4j
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

        log.debug("▶▶ Cookie header: {}", response.getHeader("Cookie"));
        String path = request.getRequestURI();

        if (path.equals("/api/login")
                || path.equals("/api/join")
                || path.equals("/api/refresh")
                || path.equals("/api/logout"))
        {
            filterChain.doFilter(request, response);
            return;
        }


        // 1) Authorization 헤더 로그
        String authHeader = request.getHeader("Authorization");
        log.debug("[JwtFilter] Authorization header: {}", authHeader);

        String token = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        // 2) 헤더 없으면 쿠키에서 추출 & 로그
        if (token == null && request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                log.debug("[JwtFilter] Cookie {}={}", cookie.getName(), cookie.getValue());
                if ("accessToken".equals(cookie.getName())) {
                    token = cookie.getValue();
                    log.debug("[JwtFilter] Token from cookie: {}", token);
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
            log.debug("[JwtFilter] Token valid, userId={}", userId);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.debug("[JwtFilter] SecurityContext set with principal={}", auth.getPrincipal());

        } catch (JwtException e) {
            log.warn("[JwtFilter] Invalid token", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid token");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
