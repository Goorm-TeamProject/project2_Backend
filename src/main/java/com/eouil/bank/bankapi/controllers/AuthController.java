package com.eouil.bank.bankapi.controllers;

import com.eouil.bank.bankapi.domains.InternalLoginResult;
import com.eouil.bank.bankapi.dtos.requests.JoinRequest;
import com.eouil.bank.bankapi.dtos.responses.JoinResponse;
import com.eouil.bank.bankapi.dtos.requests.LoginRequest;
import com.eouil.bank.bankapi.dtos.responses.LoginResponse;
import com.eouil.bank.bankapi.services.AuthService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import com.eouil.bank.bankapi.metrics.SecurityMetrics;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;
    private final SecurityMetrics securityMetrics;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @PostMapping("/join")
    public ResponseEntity<JoinResponse> join(@Valid @RequestBody JoinRequest joinRequest) {
        log.info("[POST /join] 회원가입 요청: {}", joinRequest);
        JoinResponse joinResponse = authService.join(joinRequest);
        log.info("[POST /join] 회원가입 완료: {}", joinResponse);
        return ResponseEntity.ok(joinResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @RequestBody LoginRequest loginRequest,
            HttpServletResponse response
    ) {
        log.info("[LOGIN] 요청 - email: {}", loginRequest.getEmail());
        InternalLoginResult result = authService.login(loginRequest);
        log.info("[LOGIN] 성공 - email: {}, MFA 등록 여부: {}", loginRequest.getEmail(), result.isMfaRegistered());

        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", result.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(Duration.ofMinutes(5))
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", result.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(Duration.ofDays(7))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok(new LoginResponse(result.getRefreshToken(), result.isMfaRegistered()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(
            @CookieValue("refreshToken") String refreshToken,
            HttpServletResponse response
    ) {
        log.info("[REFRESH] 요청 - refreshToken 수신됨");
        InternalLoginResult result = authService.refreshAccessToken(refreshToken);

        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", result.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(Duration.ofMinutes(5))
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", result.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(Duration.ofDays(7))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok(new LoginResponse(result.getRefreshToken(), result.isMfaRegistered()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            @CookieValue(value = "accessToken", required = false) String token,
            HttpServletResponse response
    ) {
        log.info("[LOGOUT] 요청 - accessToken 쿠키: {}", token);

        // 토큰이 있으면 서비스에 전달
        if (token != null && !token.isBlank()) {
            authService.logout(token);
        }

        // 쿠키 삭제 (accessToken, refreshToken 둘 다)
        ResponseCookie deleteAccess = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(0)
                .build();

        ResponseCookie deleteRefresh = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .path("/")
                .domain(".eouil.com")
                .sameSite("None")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, deleteRefresh.toString());

        return ResponseEntity.ok(Map.of("success", true));
    }


    @GetMapping("/mfa/setup")
    public ResponseEntity<?> setupMfa(
            @CookieValue(value = "accessToken", required = false) String token
    ) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Missing access token."));
        }
        String otpUrl = authService.generateOtpUrlByToken(token);
        log.info("[GET /mfa/setup] MFA URL 생성 완료");
        return ResponseEntity.ok(Map.of("otpUrl", otpUrl));
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<?> verifyMfa(
            @RequestBody Map<String, String> payload,
            HttpServletResponse response
    ) {
        String email = payload.get("email");
        int code = Integer.parseInt(payload.get("code"));

        boolean passed = authService.verifyCode(email, code);
        if (passed) {
            String userId = authService.getUserIdByEmail(email);
            String newToken = jwtUtil.generateAccessToken(userId, true);

            ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", newToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .domain(".eouil.com")
                    .sameSite("None")
                    .maxAge(Duration.ofMinutes(5))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
            log.info("[POST /mfa/verify] MFA 통과, accessToken 재발급");

            return ResponseEntity.ok(Map.of("success", true));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("success", false));
    }
}
