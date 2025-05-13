package com.eouil.bank.bankapi.services;

import com.eouil.bank.bankapi.domains.User;
import com.eouil.bank.bankapi.dtos.requests.CreateAccountRequest;
import com.eouil.bank.bankapi.dtos.requests.JoinRequest;
import com.eouil.bank.bankapi.dtos.requests.LoginRequest;
import com.eouil.bank.bankapi.dtos.responses.JoinResponse;
import com.eouil.bank.bankapi.dtos.responses.LoginResponse;
import com.eouil.bank.bankapi.exceptions.*;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.utils.JwtUtil;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.UUID;

@Slf4j
@Service
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();
    private final Environment env;
    private final RedisTemplate<String, String> redisTemplate;

    private final AccountService accountService;
    private final RedisTokenService redisTokenService;
    private final JwtUtil jwtUtil;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       Environment env,
                       RedisTemplate<String, String> redisTemplate,
                       AccountService accountService,
                       RedisTokenService redisTokenService,
                       JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.env = env;
        this.redisTemplate = redisTemplate;
        this.accountService = accountService;
        this.redisTokenService = redisTokenService;
        this.jwtUtil = jwtUtil;
    }

    public boolean isLocal() {
        return Arrays.asList(env.getActiveProfiles()).contains("local");
    }

    public JoinResponse join(JoinRequest joinRequest) {
        log.info("➡️ [JOIN] 요청 - email: {}", joinRequest.email);

        if (userRepository.findByEmail(joinRequest.email).isPresent()) {
            log.warn("[JOIN] 중복 이메일 시도 - {}", joinRequest.email);
            throw new DuplicateEmailException();
        }

        String userId = UUID.randomUUID().toString();
        User user = new User();
        user.setUserId(userId);
        user.setName(joinRequest.name);
        user.setEmail(joinRequest.email);
        user.setPassword(passwordEncoder.encode(joinRequest.password));
        userRepository.save(user);

        CreateAccountRequest acctReq = new CreateAccountRequest();
        acctReq.setBalance(BigDecimal.valueOf(0));  // 초기 잔액을 0원으로 설정
        accountService.createAccount(acctReq, userId);
        log.info("[JOIN] 자동 계좌 생성 완료 - userId: {}, initialBalance: {}", userId, 0);

        log.info("[JOIN] 완료 - userId: {}, email: {}", userId, user.getEmail());
        return new JoinResponse(user.getName(), user.getEmail());
    }

    public LoginResponse login(LoginRequest loginRequest) {
        log.info("[LOGIN] 요청 - email: {}", loginRequest.email);

        User user = userRepository.findByEmail(loginRequest.email)
                .orElseThrow(() -> new UserNotFoundException(loginRequest.email));

        if (!passwordEncoder.matches(loginRequest.password, user.getPassword())) {
            throw new InvalidPasswordException();
        }

        String accessToken = jwtUtil.generateAccessToken(user.getUserId(),false);
        String refreshToken = jwtUtil.generateRefreshToken(user.getUserId());

        // Redis에 리프레시 토큰 저장
        redisTokenService.saveRefreshToken(user.getUserId(), refreshToken, jwtUtil.getRefreshTokenExpireMillis());

        boolean mfaRegistered = user.getMfaSecret() != null;

        log.info("[LOGIN] 성공 - userId: {}, MFA 등록 여부: {}", user.getUserId(), mfaRegistered);
        return new LoginResponse(accessToken, refreshToken, mfaRegistered);
    }


    // 토큰 재발급 요청
    public LoginResponse refreshAccessToken(String refreshToken) {
        log.info("[REFRESH] 요청");

        String userId = jwtUtil.validateTokenAndGetUserId(refreshToken);
        String storedRefreshToken = redisTokenService.getRefreshToken(userId);

        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new InvalidRefreshTokenException();
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));

        String newAccessToken = jwtUtil.generateAccessToken(userId);
        boolean mfaRegistered = user.getMfaSecret() != null;

        return new LoginResponse(newAccessToken, refreshToken, mfaRegistered); // 이게 핵심!
    }


    public void logout(String token) {
        log.info("[LOGOUT] 요청");

        if (token == null || token.isEmpty()) {
            throw new TokenMissingException();
        }

        String userId = jwtUtil.validateTokenAndGetUserId(token);

        // 리프레시 토큰 redis에서 삭제
        redisTokenService.deleteRefreshToken(userId);

        // Access Token 남은 시간 계산 (시간 음수 결과값 방지 포함)
        long expireMillis = Math.max(0, jwtUtil.getExpiration(token) - System.currentTimeMillis());

        // redis에 블랙리스트 등록
        redisTokenService.addToBlacklist(token, expireMillis);

        log.info("[LOGOUT] 완료 - userId: {}", userId);
    }

    public String generateOtpUrlByToken(String token) {
        String userId = jwtUtil.validateTokenAndGetUserId(token);
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));

        String secret = gAuth.createCredentials().getKey();
        try {
            saveSecret(user, secret);  // Redis or H2 저장 로직 분기
        } catch (Exception e) {
            log.warn("❗ Redis 저장 실패 → fallback to H2 저장: {}", e.getMessage());
            saveSecretToH2(user.getEmail(), secret);
        }

        return String.format("otpauth://totp/%s?secret=%s&issuer=EouilBank", user.getEmail(), secret);
    }

    public boolean verifyCode(String email, int code) {
        String secret = isLocal() ? getSecretFromH2(email) : getSecretFromRedis(email);
        return gAuth.authorize(secret, code);
    }

    private void saveSecretToH2(String email, String secret) {
        User user = userRepository.findByEmail(email).orElseThrow(() -> new UserNotFoundException(email));
        user.setMfaSecret(secret);
        userRepository.save(user);
    }

    private String getSecretFromH2(String email) {
        return userRepository.findByEmail(email)
                .map(User::getMfaSecret)
                .orElseThrow(() -> new MfaSecretNotFoundException("H2에서 " + email));
    }

    private void saveSecretToRedis(String email, String secret) {
        redisTemplate.opsForHash().put("MFA:SECRETS", email, secret);
    }

    private String getSecretFromRedis(String email) {
        Object secret = redisTemplate.opsForHash().get("MFA:SECRETS", email);
        if (secret == null) throw new MfaSecretNotFoundException("Redis에서 " + email);
        return (String) secret;
    }

    private void saveSecret(User user, String secret) {
        if (isLocal()) {
            saveSecretToH2(user.getEmail(), secret);
        } else {
            saveSecretToRedis(user.getEmail(), secret);
        }
    }
    public String getUserIdByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(User::getUserId)
                .orElseThrow(() -> new UserNotFoundException(email));
    }

}
