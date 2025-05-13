package com.eouil.bank.bankapi.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;

@Profile("dev")
@Service
@Slf4j
public class DummyAlertService extends AlertService {
    public DummyAlertService() {
        super(null);  // 또는 SesClient를 Optional로 바꾸는 구조로 변경
    }

    @Override
    public void sendSuspiciousWithdrawalEmail(String toEmail, String accountNumber, BigDecimal amount) {
        log.info("[DEV-ALERT] 메일 대신 로그 출력: {}, {}, {}", toEmail, accountNumber, amount);
    }
}

