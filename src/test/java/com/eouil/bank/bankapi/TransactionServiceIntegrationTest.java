package com.eouil.bank.bankapi;

import com.eouil.bank.bankapi.domains.*;
import com.eouil.bank.bankapi.dtos.requests.DepositRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.TransferRequestDTO;
import com.eouil.bank.bankapi.dtos.requests.WithdrawRequestDTO;
import com.eouil.bank.bankapi.dtos.responses.TransactionResponseDTO;
import com.eouil.bank.bankapi.repositories.AccountRepository;
import com.eouil.bank.bankapi.repositories.TransactionRepository;
import com.eouil.bank.bankapi.repositories.UserRepository;
import com.eouil.bank.bankapi.services.TransactionService;
import com.eouil.bank.bankapi.services.AlertService;
import com.eouil.bank.bankapi.utils.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
public class TransactionServiceIntegrationTest {

    @Autowired
    private TransactionService transactionService;

    @MockBean
    private AccountRepository accountRepository;

    @MockBean
    private TransactionRepository transactionRepository;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private JwtUtil jwtUtil;

    @MockBean
    private AlertService alertService;

    private User mockUser;
    private String token;

    @BeforeEach
    void setup() {
        mockUser = new User();
        mockUser.setUserId("user-123");
        mockUser.setEmail("user@test.com");

        token = "mock-token";

        when(jwtUtil.validateTokenAndGetUserId(token)).thenReturn("user-123");
        when(userRepository.findById("user-123")).thenReturn(java.util.Optional.of(mockUser));

        // transactionId 자동 할당 mock
        when(transactionRepository.save(any(Transaction.class))).thenAnswer(invocation -> {
            Transaction tx = invocation.getArgument(0);
            tx.setTransactionId(1L);
            return tx;
        });
    }

    @Test
    void testDeposit_success() {
        Account to = new Account();
        to.setAccountNumber("333-444");
        to.setBalance(new BigDecimal("15000"));
        to.setUser(mockUser);

        when(accountRepository.findByAccountNumberForUpdate("333-444")).thenReturn(to);
        when(accountRepository.save(any())).thenReturn(to);

        DepositRequestDTO request = new DepositRequestDTO("333-444", new BigDecimal("5000"), "메모");
        TransactionResponseDTO result = transactionService.deposit(request, token);

        System.out.println("[Deposit] 입금 후 계좌 잔액: " + result.getBalanceAfter());

        assertNotNull(result.getTransactionID());
        assertEquals("DEPOSIT", result.getType());
        assertEquals(new BigDecimal("20000"), result.getBalanceAfter());
    }

    @Test
    void testWithdraw_success() {
        Account from = new Account();
        from.setAccountNumber("111-222");
        from.setBalance(new BigDecimal("10000"));
        from.setUser(mockUser);

        when(accountRepository.findByAccountNumberForUpdate("111-222")).thenReturn(from);
        when(accountRepository.save(any())).thenReturn(from);

        WithdrawRequestDTO request = new WithdrawRequestDTO("111-222", new BigDecimal("3000"), "ATM 출금");
        TransactionResponseDTO result = transactionService.withdraw(request, token);

        System.out.println("[WITHDRAWAL] 출금 후 계좌 잔액: " + result.getBalanceAfter());

        assertNotNull(result.getTransactionID());
        assertEquals("WITHDRAWAL", result.getType());
        assertEquals(new BigDecimal("7000"), result.getBalanceAfter());
    }

    @Test
    void testTransfer_success() {
        Account from = new Account();
        from.setAccountNumber("111-222");
        from.setBalance(new BigDecimal("10000"));
        from.setUser(mockUser);

        Account to = new Account();
        to.setAccountNumber("333-444");
        to.setBalance(new BigDecimal("2000"));
        to.setUser(mockUser);

        when(accountRepository.findByAccountNumberForUpdate("111-222")).thenReturn(from);
        when(accountRepository.findByAccountNumberForUpdate("333-444")).thenReturn(to);
        when(accountRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        TransferRequestDTO request = new TransferRequestDTO("111-222", "333-444", new BigDecimal("5000"), "친구 송금");
        TransactionResponseDTO result = transactionService.transfer(request, token);

        System.out.println("[Transfer_from] 송금 완료 후 출금 계좌 잔액 (from): " + result.getBalanceAfter());
        System.out.println("[Transfer_to] 송금 완료 후 입금 계좌 잔액 (to): " + to.getBalance());

        assertNotNull(result.getTransactionID());
        assertEquals("TRANSFER", result.getType());
        assertEquals(new BigDecimal("5000"), result.getBalanceAfter());
    }

    @Test
    void testTransfer_insufficientFunds_shouldThrow() {
        Account from = new Account();
        from.setAccountNumber("111-222");
        from.setBalance(new BigDecimal("500"));
        from.setUser(mockUser);

        Account to = new Account();
        to.setAccountNumber("333-444");
        to.setBalance(new BigDecimal("10000"));
        to.setUser(mockUser);

        when(accountRepository.findByAccountNumberForUpdate("111-222")).thenReturn(from);
        when(accountRepository.findByAccountNumberForUpdate("333-444")).thenReturn(to);

        TransferRequestDTO request = new TransferRequestDTO("111-222", "333-444", new BigDecimal("100000"), "부족");

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                transactionService.transfer(request, token)
        );

        assertEquals("Insufficient funds", ex.getMessage());
    }

    @Test
    void testTransfer_shouldRollback_onException() {
        Account from = new Account();
        from.setAccountNumber("111-222");
        from.setBalance(new BigDecimal("10000"));
        from.setUser(mockUser);

        Account to = new Account();
        to.setAccountNumber("333-444");
        to.setBalance(new BigDecimal("2000"));
        to.setUser(mockUser);

        when(accountRepository.findByAccountNumberForUpdate("111-222")).thenReturn(from);
        when(accountRepository.findByAccountNumberForUpdate("333-444")).thenReturn(null); // 일부러 에러 유도

        BigDecimal transferAmount = new BigDecimal("5000");

        System.out.println("[Rollback - 송금 전] 출금 계좌 잔액 (from): " + from.getBalance());
        System.out.println("[Rollback - 송금 전] 입금 계좌 잔액 (to):   " + to.getBalance());
        System.out.println("[Rollback - 요청 송금 금액]: " + transferAmount);

        TransferRequestDTO request = new TransferRequestDTO("111-222", "333-444", transferAmount, "롤백 테스트");

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                transactionService.transfer(request, token)
        );

        System.out.println("[Rollback - 예외 발생] 메시지: " + ex.getMessage());

        // 롤백 확인용 로그
        System.out.println("[Rollback - 송금 후] 출금 계좌 잔액 (from): " + from.getBalance());
        System.out.println("[Rollback - 송금 후] 입금 계좌 잔액 (to):   " + to.getBalance());

        // 실제로 금액이 빠지지 않았는지 검증
        assertEquals("From or To Account not found", ex.getMessage());
        assertEquals(new BigDecimal("10000"), from.getBalance(), "잔액은 롤백되어야 함");
        assertEquals(new BigDecimal("2000"), to.getBalance(), "입금 계좌는 건드리지 않았어야 함");
    }

    @Test
    void testWithdraw_shouldRollback_onInvalidAccount() {
        // 출금 대상 계좌는 존재하지 않는다고 가정 (null 리턴)
        when(accountRepository.findByAccountNumberForUpdate("111-222")).thenReturn(null);

        WithdrawRequestDTO request = new WithdrawRequestDTO("111-222", new BigDecimal("5000"), "잘못된 계좌");

        // 계좌 객체를 만들어도 실제 저장소에서는 null 반환 → 실제 DB에 영향 없음
        Account dummy = new Account();
        dummy.setAccountNumber("111-222");
        dummy.setBalance(new BigDecimal("10000"));
        dummy.setUser(mockUser);

        // 롤백 검증용 잔액 출력
        System.out.println("[Withdraw Rollback - Invalid Account] 출금 요청 전 잔액: " + dummy.getBalance());

        RuntimeException ex = assertThrows(RuntimeException.class, () ->
                transactionService.withdraw(request, token)
        );

        // 예외 메시지 및 상태 확인
        System.out.println("[Withdraw Rollback - Invalid Account] 예외 발생: " + ex.getMessage());
        System.out.println("[Withdraw Rollback - Invalid Account] 출금 후 잔액: " + dummy.getBalance());

        assertEquals("From Account not found", ex.getMessage());
        assertEquals(new BigDecimal("10000"), dummy.getBalance(), "잔액은 롤백되어야 함");
    }
}
