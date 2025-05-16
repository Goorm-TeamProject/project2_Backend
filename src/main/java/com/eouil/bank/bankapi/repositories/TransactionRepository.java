package com.eouil.bank.bankapi.repositories;

import com.eouil.bank.bankapi.domains.Transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    @Query("SELECT t FROM Transaction t " +
            "WHERE t.fromAccount.accountNumber = :accountNumber " +
            "OR t.toAccount.accountNumber = :accountNumber")
    List<Transaction> findByAccountNumber(@Param("accountNumber") String accountNumber);

    List<Transaction> findByFromAccount_User_UserIdOrToAccount_User_UserIdOrderByCreatedAtAsc(
            String fromUserId,
            String toUserId
    );
}
