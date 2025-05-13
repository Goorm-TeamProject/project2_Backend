package com.eouil.bank.bankapi.services;

import com.eouil.bank.bankapi.domains.*;
import com.eouil.bank.bankapi.dtos.requests.DepositRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.TransferRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.WithdrawRequestDTO;
import com.eouil.bank.bankapi.dtos.responses.TransactionResponseDTO;
import com.eouil.bank.bankapi.repositories.AccountRepository;
import com.eouil.bank.bankapi.repositories.TransactionRepository;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.utils.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class TransactionService {

    private final UserRepository userRepository;
    private final AccountRepository accountRepository;
    private final TransactionRepository transactionRepository;
    private final JwtUtil jwtUtil;
    private final AlertService alertService;

    @Transactional
    public TransactionResponseDTO transfer(TransferRequestDTO request, String token) {
        String userId = jwtUtil.validateTokenAndGetUserId(token);
        log.info("[TRANSFER] 요청 - 사용자: {}, 출금계좌: {}, 입금계좌: {}, 금액: {}", userId, request.getFromAccountNumber(), request.getToAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Account fromAccount = accountRepository.findByAccountNumberForUpdate(request.getFromAccountNumber());
        Account toAccount = accountRepository.findByAccountNumberForUpdate(request.getToAccountNumber());

        if (fromAccount == null || toAccount == null) {
            throw new RuntimeException("From or To Account not found");
        }

        if (!fromAccount.getUser().getUserId().equals(user.getUserId())) {
            log.warn("[TRANSFER] 인증 실패 - 사용자 {}가 계좌 {}에 접근", userId, fromAccount.getAccountNumber());
            throw new SecurityException("Unauthorized access to account");
        }

        if (fromAccount.getBalance().compareTo(request.getAmount()) < 0) {
            log.warn("[TRANSFER] 잔액 부족 - 계좌 {}, 잔액 {}, 요청금액 {}", fromAccount.getAccountNumber(), fromAccount.getBalance(), request.getAmount());
            throw new RuntimeException("Insufficient funds");
        }

        fromAccount.setBalance(fromAccount.getBalance().subtract(request.getAmount()));
        toAccount.setBalance(toAccount.getBalance().add(request.getAmount()));
        accountRepository.save(fromAccount);
        accountRepository.save(toAccount);

        Transaction tx = Transaction.builder()
                .fromAccount(fromAccount)
                .toAccount(toAccount)
                .type(TransactionType.TRANSFER)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(fromAccount.getBalance())
                .createdAt(LocalDateTime.now())
                .build();

        transactionRepository.save(tx);

        log.info("[TRANSFER] 완료 - 트랜잭션 ID: {}", tx.getTransactionId());
        return buildResponse(tx);
    }

    @Transactional
    public TransactionResponseDTO withdraw(WithdrawRequestDTO request, String token) {
        String userId = jwtUtil.validateTokenAndGetUserId(token);
        log.info("[WITHDRAW] 요청 - 사용자: {}, 출금계좌: {}, 금액: {}", userId, request.getFromAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Account fromAccount = accountRepository.findByAccountNumberForUpdate(request.getFromAccountNumber());
        if (fromAccount == null) {
            throw new RuntimeException("From Account not found");
        }

        if (!fromAccount.getUser().getUserId().equals(user.getUserId())) {
            log.warn("[WITHDRAW] 인증 실패 - 사용자 {}가 계좌 {}에 접근", userId, fromAccount.getAccountNumber());
            throw new SecurityException("Unauthorized access to account");
        }

        if (fromAccount.getBalance().compareTo(request.getAmount()) < 0) {
            log.warn("[WITHDRAW] 잔액 부족 - 계좌 {}, 잔액 {}, 요청금액 {}", fromAccount.getAccountNumber(), fromAccount.getBalance(), request.getAmount());
            throw new RuntimeException("Insufficient funds");
        }

        // 이상금액 알림
        BigDecimal limit = new BigDecimal("1000000");
        if (request.getAmount().compareTo(limit) >= 0) {
            log.warn("[WITHDRAW] 알림 - 계좌 {}에서 {} 이상 출금", fromAccount.getAccountNumber(), limit);
            alertService.sendSuspiciousWithdrawalEmail(user.getEmail(), fromAccount.getAccountNumber(), request.getAmount());
        }

        fromAccount.setBalance(fromAccount.getBalance().subtract(request.getAmount()));
        accountRepository.save(fromAccount);

        Transaction tx = Transaction.builder()
                .fromAccount(fromAccount)
                .type(TransactionType.WITHDRAWAL)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(fromAccount.getBalance())
                .createdAt(LocalDateTime.now())
                .build();

        transactionRepository.save(tx);
        log.info("[WITHDRAW] 완료 - 트랜잭션 ID: {}", tx.getTransactionId());

        return buildResponse(tx);
    }

    @Transactional
    public TransactionResponseDTO deposit(DepositRequestDTO request, String token) {
        String userId = jwtUtil.validateTokenAndGetUserId(token);
        log.info("[DEPOSIT] 요청 - 사용자: {}, 입금계좌: {}, 금액: {}", userId, request.getToAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Account toAccount = accountRepository.findByAccountNumberForUpdate(request.getToAccountNumber());
        if (toAccount == null) {
            throw new RuntimeException("To Account not found");
        }

        if (!toAccount.getUser().getUserId().equals(user.getUserId())) {
            log.warn("[DEPOSIT] 인증 실패 - 사용자 {}가 계좌 {}에 접근", userId, toAccount.getAccountNumber());
            throw new SecurityException("Unauthorized access to account");
        }

        toAccount.setBalance(toAccount.getBalance().add(request.getAmount()));
        accountRepository.save(toAccount);

        Transaction tx = Transaction.builder()
                .toAccount(toAccount)
                .type(TransactionType.DEPOSIT)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(toAccount.getBalance())
                .createdAt(LocalDateTime.now())
                .build();

        transactionRepository.save(tx);
        log.info("[DEPOSIT] 완료 - 트랜잭션 ID: {}", tx.getTransactionId());

        return buildResponse(tx);
    }

    public List<TransactionResponseDTO> getTransactions(String token) {
        String userId = jwtUtil.validateTokenAndGetUserId(token);
        log.info("[GET TRANSACTIONS] 요청 - 사용자: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Account> accounts = accountRepository.findByUser(user);
        List<Transaction> allTransactions = new ArrayList<>();
        for (Account ac : accounts) {
            allTransactions.addAll(transactionRepository.findByAccountNumber(ac.getAccountNumber()));
        }

        log.info("[GET TRANSACTIONS] 완료 - 총 트랜잭션 수: {}", allTransactions.size());
        return allTransactions.stream()
                .map(this::buildResponse)
                .collect(Collectors.toList());
    }

    private TransactionResponseDTO buildResponse(Transaction tx) {
        return TransactionResponseDTO.builder()
                .transactionID(tx.getTransactionId())
                .fromAccountNumber(tx.getFromAccount() != null ? tx.getFromAccount().getAccountNumber() : null)
                .toAccountNumber(tx.getToAccount() != null ? tx.getToAccount().getAccountNumber() : null)
                .type(tx.getType().name())
                .amount(tx.getAmount())
                .memo(tx.getMemo())
                .status(tx.getStatus().name())
                .balanceAfter(tx.getBalanceAfter())
                .createdAt(tx.getCreatedAt())
                .build();
    }
}
