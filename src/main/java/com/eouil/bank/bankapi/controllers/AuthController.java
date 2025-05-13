package com.eouil.bank.bankapi.controllers;

import com.eouil.bank.bankapi.dtos.requests.JoinRequest;
import com.eouil.bank.bankapi.dtos.responses.JoinResponse;
import com.eouil.bank.bankapi.dtos.requests.LoginRequest;
import com.eouil.bank.bankapi.dtos.responses.LoginResponse;
import com.eouil.bank.bankapi.dtos.responses.LogoutResponse;
import com.eouil.bank.bankapi.services.AuthService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.eouil.bank.bankapi.metrics.SecurityMetrics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @Autowired
    private SecurityMetrics securityMetrics;

    @PostMapping("/join")
    public ResponseEntity<JoinResponse> join(@Valid @RequestBody JoinRequest joinRequest) {
        log.info("[POST /join] 회원가입 요청: {}", joinRequest);
        JoinResponse joinResponse = authService.join(joinRequest);
        log.info("[POST /join] 회원가입 완료: {}", joinResponse);
        return ResponseEntity.ok(joinResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        log.info("[POST /login] 로그인 요청: {}", loginRequest);
        try {
            LoginResponse loginResponse = authService.login(loginRequest);
            log.info("[POST /login] 로그인 성공: {}", loginResponse);
            return ResponseEntity.ok(loginResponse);
        } catch (BadCredentialsException e) {
            // 로그인 실패시 메트릭 증가
            securityMetrics.incrementLoginFailure();
            log.warn("[POST /login] 로그인 실패: 잘못된 자격 증명");
            throw e;
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@RequestHeader("Authorization") String refreshToken) {
        log.info("[POST /refresh] 토큰 갱신 요청");
        if (refreshToken.startsWith("Bearer ")) {
            refreshToken = refreshToken.substring(7);
        }

        LoginResponse response = authService.refreshAccessToken(refreshToken);
        log.info("[POST /refresh] accessToken 재발급 완료 - MFA 등록 여부: {}", response.isMfaRegistered());
        return ResponseEntity.ok(response);
    }


    @PostMapping("/logout")
    public ResponseEntity<LogoutResponse> logout(@RequestHeader("Authorization") String token, HttpServletResponse response) {
        log.info("[POST /logout] 로그아웃 요청");
        if (token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        authService.logout(token);
        log.info("[POST /logout] 로그아웃 완료");

        Cookie cookie = new Cookie("accessToken", null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok(new LogoutResponse("로그아웃 완료"));
    }

    @GetMapping("/mfa/setup")
    public ResponseEntity<?> setupMfa(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.startsWith("Bearer ") ? authHeader.substring(7) : authHeader;
        String otpUrl = authService.generateOtpUrlByToken(token);

        log.info("[GET /mfa/setup] MFA URL 생성 완료");
        return ResponseEntity.ok(Map.of("otpUrl", otpUrl));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<?> verifyMfa(@RequestBody Map<String, String> payload, HttpServletResponse response) {
        String email = payload.get("email");
        int code = Integer.parseInt(payload.get("code"));

        boolean result = authService.verifyCode(email, code);

        if (result) {
            String userId = authService.getUserIdByEmail(email);
            String verifiedAccessToken = jwtUtil.generateAccessToken(userId, true);

            Cookie cookie = new Cookie("accessToken", verifiedAccessToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/");
            response.addCookie(cookie);

            return ResponseEntity.ok(Map.of("success", true));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("success", false));
    }

}