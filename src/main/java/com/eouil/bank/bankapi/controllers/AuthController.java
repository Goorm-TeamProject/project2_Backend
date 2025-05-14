package com.eouil.bank.bankapi.controllers;

import com.eouil.bank.bankapi.domains.InternalLoginResult;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.eouil.bank.bankapi.metrics.SecurityMetrics;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;

import java.time.Duration;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @Value("${jwt.secret}")
    private String jwtSecret;

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
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {
        log.info("[LOGIN] 요청 - email: {}", loginRequest.getEmail());

        InternalLoginResult result = authService.login(loginRequest);

        log.info("[LOGIN] 성공 - userId: {}, MFA 등록 여부: {}", loginRequest.getEmail(), result.isMfaRegistered());

        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", result.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofMinutes(5))
                .sameSite("None")
                .build();

        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", result.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofDays(7))
                .sameSite("None")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok(new LoginResponse(result.getRefreshToken(), result.isMfaRegistered()));
    }



    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue("refreshToken") String refreshToken,
                                                 HttpServletResponse response) {
        log.info("[REFRESH] 요청 - refreshToken 수신됨");

        InternalLoginResult result = authService.refreshAccessToken(refreshToken);

        // accessToken → 쿠키에 저장
        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", result.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofMinutes(5))
                .sameSite("None")
                .build();

        // ✅ refreshToken도 쿠키로 재설정 (선택이지만 보통 UX 상 안정적)
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", result.getRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofDays(7))
                .sameSite("None")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok(new LoginResponse(result.getRefreshToken(), result.isMfaRegistered()));
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(value = "accessToken", required = false) String token,
                                    HttpServletResponse response) {
        if (token != null) {
            authService.logout(token);
        }

        Cookie cookie = new Cookie("accessToken", null); // 쿠키 삭제
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 삭제
        response.addCookie(cookie);

        return ResponseEntity.ok().build();
    }

    @GetMapping("/mfa/setup")
    public ResponseEntity<?> setupMfa(@CookieValue(value = "accessToken", required = false) String token) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Missing access token.");
        }

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