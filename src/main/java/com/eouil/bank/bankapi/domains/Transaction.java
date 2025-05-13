package com.eouil.bank.bankapi.domains;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long transactionId;

    @ManyToOne
    @JoinColumn(name = "fromAccountNumber")
    private Account fromAccount;

    @ManyToOne
    @JoinColumn(name = "toAccountNumber")
    private Account toAccount;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TransactionType type;

    @Column(nullable = false)
    private BigDecimal amount;

    @Column(nullable = true)
    private String memo;

    @Enumerated(EnumType.STRING)
    private TransactionStatus status;

    private BigDecimal balanceAfter;

    private LocalDateTime createdAt;

    // JPA 기본 생성자
    protected Transaction() {}

    // 빌더 패턴 적용 생성자
    @Builder
    public Transaction(Account fromAccount, Account toAccount, TransactionType type, BigDecimal amount, String memo, TransactionStatus status, BigDecimal balanceAfter,LocalDateTime createdAt) {
        this.fromAccount = fromAccount;
        this.toAccount = toAccount;
        this.type = type;
        this.amount = amount;
        this.memo = memo;
        this.status = status != null ? status : TransactionStatus.PENDING;
        this.balanceAfter = balanceAfter;
        this.createdAt = createdAt;
    }

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
    }
}
