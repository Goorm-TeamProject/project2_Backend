package com.eouil.bank.bankapi.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                // 서브도메인(+메인 도메인) 전부 허용
                .allowedOriginPatterns("https://*.eouil.com", "https://eouil.com")
                // 크로스사이트 요청에 쿠키 전송 허용
                .allowCredentials(true)
                // 허용 메서드
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                // 허용 헤더
                .allowedHeaders("*")
                // 클라이언트에서 Set-Cookie 헤더를 볼 수 있게
                .exposedHeaders("Set-Cookie");
    }
}