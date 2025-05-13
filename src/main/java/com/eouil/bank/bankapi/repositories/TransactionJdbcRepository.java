package com.eouil.bank.bankapi.repositories;

import com.eouil.bank.bankapi.domains.Transaction;
import com.eouil.bank.bankapi.domains.TransactionSaver;
import com.eouil.bank.bankapi.domains.TransactionType;
import org.springframework.transaction.annotation.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
@RequiredArgsConstructor
public class TransactionJdbcRepository implements TransactionSaver {

    private final JdbcTemplate jdbcTemplate;

    @Transactional
    public void save(Transaction tx) {
        if (tx.getType() == TransactionType.DEPOSIT) {
            saveDeposit(tx);
        } else if (tx.getType() == TransactionType.WITHDRAWAL) {
            saveWithdrawal(tx);
        } else if (tx.getType() == TransactionType.TRANSFER) {
            saveTransfer(tx);
        } else {
            throw new IllegalArgumentException("지원하지 않는 트랜잭션 타입입니다: " + tx.getType());
        }
    }

    private void saveDeposit(Transaction tx) {
        String sql = "INSERT INTO transaction (to_account_number, type, amount, memo, status, balance_after, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        jdbcTemplate.update(sql,
                tx.getToAccount().getAccountNumber(),
                tx.getType().name(),
                tx.getAmount(),
                tx.getMemo(),
                tx.getStatus().name(),
                tx.getBalanceAfter(),
                LocalDateTime.now()
        );
    }

    private void saveWithdrawal(Transaction tx) {
        String sql = "INSERT INTO transaction (from_account_number, type, amount, memo, status, balance_after, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?)";
        jdbcTemplate.update(sql,
                tx.getFromAccount().getAccountNumber(),
                tx.getType().name(),
                tx.getAmount(),
                tx.getMemo(),
                tx.getStatus().name(),
                tx.getBalanceAfter(),
                LocalDateTime.now()
        );
    }

    private void saveTransfer(Transaction tx) {
        String sql = "INSERT INTO transaction (from_account_number, to_account_number, type, amount, memo, status, balance_after, created_at) " +
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        jdbcTemplate.update(sql,
                tx.getFromAccount().getAccountNumber(),
                tx.getToAccount().getAccountNumber(),
                tx.getType().name(),
                tx.getAmount(),
                tx.getMemo(),
                tx.getStatus().name(),
                tx.getBalanceAfter(),
                LocalDateTime.now()
        );
    }

}
