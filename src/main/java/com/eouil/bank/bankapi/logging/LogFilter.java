package com.eouil.bank.bankapi.logging;

import com.eouil.bank.bankapi.utils.JwtUtil;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
@Slf4j
public class LogFilter implements Filter {

    private static final String TRACE_ID = "traceId";
    private static final String USER_ID = "userId";
    private final JwtUtil jwtUtil;

    public LogFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String path = httpRequest.getRequestURI();

        try {
            // 1. Generate and store traceId
            String traceId = UUID.randomUUID().toString();
            MDC.put(TRACE_ID, traceId);

            // 2. Extract token from Authorization header only
            String authHeader = httpRequest.getHeader("Authorization");
            log.debug("[MDC Filter] path={} Authorization header raw: {}", path, authHeader);

            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                log.debug("[MDC Filter] path={} extracted token: {}", path, token);
                String userId = jwtUtil.validateTokenAndGetUserId(token);
                MDC.put(USER_ID, userId);
            } else {
                log.warn("[MDC Filter] path={} Missing or invalid Authorization header", path);
            }

            // 3. Continue filter chain
            chain.doFilter(request, response);

        } catch (Exception e) {
            log.warn("[MDC Filter Error] {}", e.getMessage(), e);
            chain.doFilter(request, response);
        } finally {
            MDC.clear();
        }
    }

}
