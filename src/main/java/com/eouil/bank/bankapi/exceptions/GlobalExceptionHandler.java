package com.eouil.bank.bankapi.exceptions;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import com.eouil.bank.bankapi.metrics.SecurityMetrics;
import org.springframework.beans.factory.annotation.Autowired;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @Autowired
    private SecurityMetrics securityMetrics;

    // 1. 권한 없음 (403)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        // 권한 없는 접근시 메트릭 증가
        securityMetrics.incrementUnauthorizedAccess();

        log.warn("[403] Access Denied: {}", ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(403, "접근 권한이 없습니다."));
    }

    // 2. DB 에러
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDBException(DataAccessException ex) {
        log.error("[DB Error] {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of(500, "데이터베이스 오류가 발생했습니다."));
    }

    // 3. 유효성 검증 실패 (400)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(err -> err.getDefaultMessage())
                .findFirst()
                .orElse("요청값이 잘못되었습니다.");
        log.warn("📦 [Validation Error] {}", errorMessage);
        return ResponseEntity.badRequest().body(ErrorResponse.of(400, errorMessage));
    }

    // 4. 잘못된 파라미터 (ex: id=abc → int)
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        log.warn("🔧 [Type Mismatch] {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(ErrorResponse.of(400, "요청 파라미터 타입이 잘못되었습니다."));
    }

    // 5. 알 수 없는 예외 (500)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(Exception ex) {
        log.error("[Unhandled Exception] {}", ex.getMessage(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of(500, "예기치 못한 오류가 발생했습니다."));
    }
}
