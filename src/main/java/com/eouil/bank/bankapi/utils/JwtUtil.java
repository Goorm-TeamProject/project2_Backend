package com.eouil.bank.bankapi.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.security.Key;
import java.util.Date;

@Component
@Slf4j
public class JwtUtil {
    private final Key key;
    private final long ACCESS_EXP = 1000 * 60 * 5;  // 5분
    private final long REFRESH_EXP = 1000 * 60 * 60 * 24 * 7; // 7일


    public JwtUtil(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }


    public String generateAccessToken(String userId) {
        return generateAccessToken(userId, true);
    }

    // access token
    public String generateAccessToken(String userId, boolean mfaVerified) {
        try {
            String token = Jwts.builder()
                    .setSubject(userId)
                    .claim("mfaVerified", mfaVerified)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + ACCESS_EXP))
                    .signWith(key, SignatureAlgorithm.HS256)
                    .compact();

            log.debug("[JwtUtil] accessToken 생성 성공: {}", token);  // ✅ 여기!
            return token;
        } catch (Exception e) {
            log.error("[JwtUtil] accessToken 생성 실패", e);
            throw new RuntimeException("accessToken 생성 실패", e); // ❌ null 반환 금지
        }
    }


    // refresh token
    public String generateRefreshToken(String userId) {
        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_EXP))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT 토큰을 검증하고 userId 추출
    public String validateTokenAndGetUserId(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .setAllowedClockSkewSeconds(60) // 1분 정도 시계 차이 허용
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }


    public long getAccessTokenExpireMillis() {
        return ACCESS_EXP;
    }

    public long getRefreshTokenExpireMillis() {
        return REFRESH_EXP;
    }

    public long getExpiration(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token.replace("Bearer ", ""))
                .getBody();

        return claims.getExpiration().getTime();
    }
    
}