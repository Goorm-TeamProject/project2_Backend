package com.eouil.bank.bankapi.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.ses.SesClient;
import software.amazon.awssdk.services.ses.model.*;

import java.math.BigDecimal;

@Slf4j
@Service
@RequiredArgsConstructor
public class AlertService {

    private final SesClient sesClient;

    @Value("${cloud.aws.ses.sender}")
    private String senderEmail;

    public void sendSuspiciousWithdrawalEmail(String toEmail, String accountNumber, BigDecimal amount) {
        String subject = "🚨 출금 경고 알림";
        String bodyText = String.format(
                "경고: 계좌 %s에서 %s원이 출금 시도되었습니다.\n" +
                        "출금 내역을 확인해 주세요.", accountNumber, amount.toPlainString());

        Destination destination = Destination.builder()
                .toAddresses(toEmail)
                .build();

        Content subjectContent = Content.builder()
                .data(subject)
                .charset("UTF-8")
                .build();

        Content bodyContent = Content.builder()
                .data(bodyText)
                .charset("UTF-8")
                .build();

        Body body = Body.builder()
                .text(bodyContent)
                .build();

        Message message = Message.builder()
                .subject(subjectContent)
                .body(body)
                .build();

        SendEmailRequest emailRequest = SendEmailRequest.builder()
                .destination(destination)
                .message(message)
                .source(senderEmail)
                .build();

        try {
            sesClient.sendEmail(emailRequest);
            log.info("[ALERT] 경고 메일 발송 완료: {}", toEmail);
        } catch (Exception e) {
            log.error("[ALERT] 메일 발송 실패", e);
        }
    }
}
