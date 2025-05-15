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
        config.setAllowedOrigins(List.of(
                "https://eouil.com",
                "http://localhost:5173"
        ));
        config.setAllowedMethods(List.of("*"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);
        // 필요시 클라이언트에서 노출할 헤더
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
                                           JwtAuthenticationFilter jwtAuthenticationFilter)
            throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                .httpBasic(basic -> basic.disable())

                .authorizeHttpRequests(authz -> authz
                        // 1) 모든 pre-flight OPTIONS 요청 허용
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        // 2) public API 허용
                        .requestMatchers(
                                "/api/join","/api/login","/api/refresh",
                                "/api/logout","/api/health","/api/mfa/**"
                        ).permitAll()
                        // 3) 나머지는 인증 필요
                        .anyRequest().authenticated()
                )
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
