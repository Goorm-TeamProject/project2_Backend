package com.eouil.bank.bankapi.services;

import com.eouil.bank.bankapi.domains.Account;
import com.eouil.bank.bankapi.domains.User;
import com.eouil.bank.bankapi.dtos.requests.CreateAccountRequest;
import com.eouil.bank.bankapi.dtos.responses.CreateAccountResponse;
import com.eouil.bank.bankapi.dtos.responses.GetMyAccountResponse;
import com.eouil.bank.bankapi.repositories.AccountRepository;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.utils.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Slf4j
@Service
public class AccountService {
    private final AccountRepository accountRepository;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public AccountService(AccountRepository accountRepository, UserRepository userRepository, JwtUtil jwtUtil) {
        this.accountRepository = accountRepository;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public List<GetMyAccountResponse> getMyaccount(String userId) {
        log.info("[GET MY ACCOUNT] 요청 - userId: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("[GET MY ACCOUNT] 사용자 없음 - userId: {}", userId);
                    return new RuntimeException("User not found");
                });

        List<GetMyAccountResponse> accounts = user.getAccounts().stream()
                .map(account -> new GetMyAccountResponse(
                        account.getAccountNumber(),
                        account.getBalance(),
                        account.getCreatedAt()
                ))
                .toList();

        log.info("[GET MY ACCOUNT] 조회 완료 - 계좌 수: {}", accounts.size());
        return accounts;
    }

    public CreateAccountResponse createAccount(CreateAccountRequest request, String userId) {
        log.info("[CREATE ACCOUNT] 요청 - userId: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> {
                    log.warn("[CREATE ACCOUNT] 사용자 없음 - userId: {}", userId);
                    return new RuntimeException("User not found");
                });

        String accountNumber = generateUniqueAccountNumber();

        Account account = new Account();
        account.setAccountNumber(accountNumber);
        account.setUser(user);
        account.setBalance(request.getBalance() != null ? request.getBalance() : BigDecimal.ZERO);
        account.setCreatedAt(LocalDateTime.now());

        accountRepository.save(account);

        log.info("[CREATE ACCOUNT] 계좌 생성 완료 - 계좌번호: {}, 초기잔액: {}", accountNumber, account.getBalance());

        return new CreateAccountResponse(
                account.getAccountNumber(),
                user.getUserId(),
                account.getBalance(),
                account.getCreatedAt()
        );
    }

    private String generateUniqueAccountNumber() {
        String number;
        do {
            number = String.valueOf(10000000000000L + (long) (Math.random() * 89999999999999L));
        } while (accountRepository.existsByAccountNumber(number));
        return number;
    }
}
