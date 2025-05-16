package com.eouil.bank.bankapi.config;

import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.services.RedisTokenService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 1) 전역 CORS 설정 소스
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of(
                "https://*.eouil.com",
                "https://eouil.com"
        ));
        // 2) 자격증명(쿠키) 허용
        config.setAllowCredentials(true);
        // 3) 허용 메서드
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        // 4) 모든 헤더 허용
        config.setAllowedHeaders(List.of("*"));
        // 5) 클라이언트에 노출할 헤더 (Set-Cookie)
        config.setExposedHeaders(List.of("Set-Cookie"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // 2) JWT 필터 빈
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            UserRepository userRepository,
            RedisTokenService redisTokenService,
            JwtUtil jwtUtil
    ) {
        return new JwtAuthenticationFilter(userRepository, redisTokenService, jwtUtil);
    }

    // 3) SecurityFilterChain에 람다 기반 CORS·헤더 설정 적용
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        http
                // ① CORS 필터 등록
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // ② CSRF 끄고
                .csrf(csrf -> csrf.disable())
                // ③ OPTIONS 프리플라이트는 무조건 허용
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/api/join","/api/login","/api/refresh",
                                "/api/logout","/api/health","/api/mfa/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .httpBasic(basic -> basic.disable())
                // ④ JWT 필터
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // 4) 비밀번호 인코더
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
