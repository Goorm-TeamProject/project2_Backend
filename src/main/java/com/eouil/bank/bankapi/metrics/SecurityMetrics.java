package com.eouil.bank.bankapi.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
public class SecurityMetrics {

    private final Counter jwtInvalidCounter;
    private final Counter unauthorizedAccessCounter;
    private final Counter loginFailuresCounter;
    private final Counter sensitiveDataAccessCounter;

    public SecurityMetrics(MeterRegistry registry) {
        this.jwtInvalidCounter = registry.counter("jwt_token_invalid_total");
        this.unauthorizedAccessCounter = registry.counter("unauthorized_access_attempt_total");
        this.loginFailuresCounter = registry.counter("login_failures_total");
        this.sensitiveDataAccessCounter = registry.counter("sensitive_data_access_total");
    }

    // 잘못된 JWT 토큰 발생
    public void incrementInvalidJwt() {
        jwtInvalidCounter.increment();
    }

    // 권한 없는 접근 발생
    public void incrementUnauthorizedAccess() {
        unauthorizedAccessCounter.increment();
    }

    // 로그인 실패 발생
    public void incrementLoginFailure() {
        loginFailuresCounter.increment();
    }

    // 민감 데이터 접근 발생
    public void incrementSensitiveDataAccess() {
        sensitiveDataAccessCounter.increment();
    }

    @Configuration
    public static class MeterRegistryConfig {

    }
}
