package com.eouil.bank.bankapi.controllers;

import com.eouil.bank.bankapi.domains.User;
import com.eouil.bank.bankapi.dtos.requests.DepositRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.TransferRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.WithdrawRequestDTO;
import com.eouil.bank.bankapi.dtos.responses.TransactionResponseDTO;
import com.eouil.bank.bankapi.services.TransactionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/transactions")
@RequiredArgsConstructor
public class TransactionController {

    private final TransactionService transactionService;

    @PostMapping("/transfer")
    public ResponseEntity<TransactionResponseDTO> transfer(
            @RequestBody TransferRequestDTO request,
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        String userId = user.getUserId();  // JwtAuthenticationFilter 에서 principal 을 userId 로 세팅했다고 가정
        log.info("[POST /transfer] 요청 도착 - userId: {}, payload: {}", userId, request);

        TransactionResponseDTO response = transactionService.transfer(request, userId);
        log.info("[POST /transfer] 처리 완료: {}", response);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/withdraw")
    public ResponseEntity<TransactionResponseDTO> withdraw(
            @RequestBody WithdrawRequestDTO request,
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        String userId = user.getUserId();
        log.info("[POST /withdraw] 요청 도착 - userId: {}, payload: {}", userId, request);

        TransactionResponseDTO response = transactionService.withdraw(request, userId);
        log.info("[POST /withdraw] 처리 완료: {}", response);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/deposit")
    public ResponseEntity<TransactionResponseDTO> deposit(
            @RequestBody DepositRequestDTO request,
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        String userId = user.getUserId();

        log.info("[POST /deposit] 요청 도착 - userId: {}, payload: {}", userId, request);

        TransactionResponseDTO response = transactionService.deposit(request, userId);
        log.info("[POST /deposit] 처리 완료: {}", response);

        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<List<TransactionResponseDTO>> getTransactions(
            Authentication authentication
    ) {
        User user = (User) authentication.getPrincipal();
        String userId = user.getUserId();

        log.info("[GET /transactions] 요청 도착 - userId: {}", userId);
        List<TransactionResponseDTO> transactions = transactionService.getTransactions(userId);
        log.info("[GET /transactions] 조회 완료: {}건", transactions.size());

        return ResponseEntity.ok(transactions);
    }
}
