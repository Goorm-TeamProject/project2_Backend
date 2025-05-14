package com.eouil.bank.bankapi.controllers;

import com.eouil.bank.bankapi.dtos.requests.DepositRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.TransactionHistoryRequest;
import com.eouil.bank.bankapi.dtos.requests.TransferRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.WithdrawRequestDTO;
import com.eouil.bank.bankapi.dtos.responses.TransactionHistoryResponse;
import com.eouil.bank.bankapi.dtos.responses.TransactionResponseDTO;
import com.eouil.bank.bankapi.services.TransactionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("api/transactions")
@RequiredArgsConstructor
public class TransactionController {

    private final TransactionService transactionService;

    @PostMapping("/transfer")
    public ResponseEntity<TransactionResponseDTO> transfer(
            @RequestBody TransferRequestDTO request,
            @CookieValue(value = "accessToken", required = false) String token
    ) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("[POST /transfer] 요청 도착: {}", request);
        TransactionResponseDTO response = transactionService.transfer(request, token);
        log.info("[POST /transfer] 처리 완료: {}", response);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/withdraw")
    public ResponseEntity<TransactionResponseDTO> withdraw(
            @RequestBody WithdrawRequestDTO request,
            @CookieValue(value = "accessToken", required = false) String token
    ) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("[POST /withdraw] 요청 도착: {}", request);
        TransactionResponseDTO response = transactionService.withdraw(request, token);
        log.info("[POST /withdraw] 처리 완료: {}", response);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/deposit")
    public ResponseEntity<TransactionResponseDTO> deposit(
            @RequestBody DepositRequestDTO request,
            @CookieValue(value = "accessToken", required = false) String token
    ) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("[POST /deposit] 요청 도착: {}", request);
        TransactionResponseDTO response = transactionService.deposit(request, token);
        log.info("[POST /deposit] 처리 완료: {}", response);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<List<TransactionResponseDTO>> getTransactions(
            @CookieValue(value = "accessToken", required = false) String token
    ) {
        if (token == null || token.isBlank()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        log.info("[GET /transactions] 요청 도착 (토큰 일부: {}...)", token.substring(0, Math.min(10, token.length())));
        List<TransactionResponseDTO> transactions = transactionService.getTransactions(token);
        log.info("[GET /transactions] 조회 완료: {}건", transactions.size());

        return ResponseEntity.ok(transactions);
    }
}
