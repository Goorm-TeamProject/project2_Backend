package com.eouil.bank.bankapi.services;

import com.eouil.bank.bankapi.domains.*;
import com.eouil.bank.bankapi.dtos.requests.DepositRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.TransferRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.WithdrawRequestDTO;
import com.eouil.bank.bankapi.dtos.responses.TransactionResponseDTO;
import com.eouil.bank.bankapi.repositories.AccountRepository;
import com.eouil.bank.bankapi.repositories.TransactionRepository;
import com.eouil.bank.bankapi.repositories.UserRepository;
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
    private final AlertService alertService;

    @Transactional
    public TransactionResponseDTO transfer(TransferRequestDTO request, String userId) {
        log.info("[TRANSFER] 요청 - userId: {}, from: {}, to: {}, amount: {}",
                userId, request.getFromAccountNumber(), request.getToAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Account from = accountRepository.findByAccountNumberForUpdate(request.getFromAccountNumber());
        Account to   = accountRepository.findByAccountNumberForUpdate(request.getToAccountNumber());
        if (from == null || to == null) {
            throw new RuntimeException("Account not found");
        }

        if (!from.getUser().getUserId().equals(userId)) {
            throw new SecurityException("Unauthorized access to account");
        }
        if (from.getBalance().compareTo(request.getAmount()) < 0) {
            throw new RuntimeException("Insufficient funds");
        }

        from.setBalance(from.getBalance().subtract(request.getAmount()));
        to.setBalance(to.getBalance().add(request.getAmount()));
        // JPA 영속성 컨텍스트가 변경 감지해서 자동 반영합니다

        Transaction tx = Transaction.builder()
                .fromAccount(from)
                .toAccount(to)
                .type(TransactionType.TRANSFER)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(from.getBalance())
                .createdAt(LocalDateTime.now())
                .build();
        transactionRepository.save(tx);

        log.info("[TRANSFER] 완료 - txId: {}", tx.getTransactionId());
        return buildResponse(tx);
    }

    @Transactional
    public TransactionResponseDTO withdraw(WithdrawRequestDTO request, String userId) {
        log.info("[WITHDRAW] 요청 - userId: {}, from: {}, amount: {}",
                userId, request.getFromAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Account from = accountRepository.findByAccountNumberForUpdate(request.getFromAccountNumber());
        if (from == null) throw new RuntimeException("Account not found");

        if (!from.getUser().getUserId().equals(userId)) {
            throw new SecurityException("Unauthorized access");
        }
        if (from.getBalance().compareTo(request.getAmount()) < 0) {
            throw new RuntimeException("Insufficient funds");
        }

        // 이상금액 알림
        BigDecimal limit = new BigDecimal("1000000");
        if (request.getAmount().compareTo(limit) >= 0) {
            alertService.sendSuspiciousWithdrawalEmail(user.getEmail(),
                    from.getAccountNumber(),
                    request.getAmount());
        }

        from.setBalance(from.getBalance().subtract(request.getAmount()));

        Transaction tx = Transaction.builder()
                .fromAccount(from)
                .type(TransactionType.WITHDRAWAL)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(from.getBalance())
                .createdAt(LocalDateTime.now())
                .build();
        transactionRepository.save(tx);

        log.info("[WITHDRAW] 완료 - txId: {}", tx.getTransactionId());
        return buildResponse(tx);
    }

    @Transactional
    public TransactionResponseDTO deposit(DepositRequestDTO request, String userId) {
        log.info("[DEPOSIT] 요청 - userId: {}, to: {}, amount: {}",
                userId, request.getToAccountNumber(), request.getAmount());

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Account to = accountRepository.findByAccountNumberForUpdate(request.getToAccountNumber());
        if (to == null) throw new RuntimeException("Account not found");

        if (!to.getUser().getUserId().equals(userId)) {
            throw new SecurityException("Unauthorized access");
        }

        to.setBalance(to.getBalance().add(request.getAmount()));

        Transaction tx = Transaction.builder()
                .toAccount(to)
                .type(TransactionType.DEPOSIT)
                .amount(request.getAmount())
                .memo(request.getMemo())
                .status(TransactionStatus.COMPLETED)
                .balanceAfter(to.getBalance())
                .createdAt(LocalDateTime.now())
                .build();
        transactionRepository.save(tx);

        log.info("[DEPOSIT] 완료 - txId: {}", tx.getTransactionId());
        return buildResponse(tx);
    }

    public List<TransactionResponseDTO> getTransactions(String userId) {
        log.info("[GET TRANSACTIONS] 요청 - userId: {}", userId);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        List<Transaction> all = transactionRepository
                .findByFromAccount_User_UserIdOrToAccount_User_UserIdOrderByCreatedAtAsc(userId, userId);

        log.info("[GET TRANSACTIONS] 완료 - count: {}", all.size());
        return all.stream()
                .map(this::buildResponse)
                .collect(Collectors.toList());
    }

    private TransactionResponseDTO buildResponse(Transaction tx) {
        return TransactionResponseDTO.builder()
                .transactionID(tx.getTransactionId())
                .fromAccountNumber(tx.getFromAccount() != null
                        ? tx.getFromAccount().getAccountNumber() : null)
                .toAccountNumber(tx.getToAccount() != null
                        ? tx.getToAccount().getAccountNumber() : null)
                .type(tx.getType().name())
                .amount(tx.getAmount())
                .memo(tx.getMemo())
                .status(tx.getStatus().name())
                .balanceAfter(tx.getBalanceAfter())
                .createdAt(tx.getCreatedAt())
                .build();
    }
}
