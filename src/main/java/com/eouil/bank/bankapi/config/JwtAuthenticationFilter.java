package com.eouil.bank.bankapi.config;

import com.eouil.bank.bankapi.domains.User;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.services.RedisTokenService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.eouil.bank.bankapi.metrics.SecurityMetrics;
import org.springframework.beans.factory.annotation.Autowired;

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

        // 로그인, 회원가입, 리프레시 요청은 필터 통과
        // 인증이 필요 없는 경로는 필터에서 제외
        if (path.equals("/api/login")
                || path.equals("/api/join")
                || path.equals("/api/refresh")
                || path.equals("/api/logout")
                || path.startsWith("/api/mfa/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = request.getHeader("Authorization");

        if (redisTokenService.isBlacklisted(token)) {
            throw new JwtException("Blacklisted token");
        }

        // 토큰이 없으면 인증 안된 상태로 통과 (403 발생 안 하게)
        if (token == null || !token.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        token = token.replace("Bearer ", "");
        try {
            String userId = jwtUtil.validateTokenAndGetUserId(token);

            //유저 검증
            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    user.getUserId(), null, null
            );
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (JwtException | IllegalArgumentException e) {
        //인증 실패 → 명시적으로 401 Unauthorized 반환/메트릭 증가
            securityMetrics.incrementInvalidJwt();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired token");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
