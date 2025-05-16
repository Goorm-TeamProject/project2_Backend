package com.eouil.bank.bankapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.List;

@Configuration
public class CorsConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public FilterRegistrationBean<CorsFilter> corsFilterRegistration() {
        CorsConfiguration config = new CorsConfiguration();
        // 1) 메인 도메인 + 모든 서브도메인 허용
        config.setAllowedOriginPatterns(List.of(
                "https://eouil.com",
                "https://*.eouil.com"
        ));
        // 2) 자격증명(쿠키) 포함 허용
        config.setAllowCredentials(true);
        // 3) 모든 HTTP 메서드 허용
        config.addAllowedMethod(CorsConfiguration.ALL);
        // 4) 모든 헤더 허용
        config.addAllowedHeader(CorsConfiguration.ALL);
        // 5) 클라이언트에서 Set-Cookie 헤더를 볼 수 있도록 노출
        config.addExposedHeader("Set-Cookie");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 모든 경로에 대해 위 설정 적용
        source.registerCorsConfiguration("/**", config);

        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(source));
        // 가장 먼저 실행되도록 우선순위 최상위 지정
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }
}
