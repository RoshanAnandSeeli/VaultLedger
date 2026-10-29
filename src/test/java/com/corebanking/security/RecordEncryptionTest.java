package com.corebanking.security;

import com.corebanking.config.DatabaseConnection;
import com.corebanking.config.DatabaseInitializer;
import com.corebanking.enums.AccountType;
import com.corebanking.model.Account;
import com.corebanking.model.Bank;
import com.corebanking.model.Transaction;
import com.corebanking.repository.AccountRepository;
import com.corebanking.repository.BankRepository;
import com.corebanking.repository.LedgerRepository;
import com.corebanking.repository.TransactionRepository;
import com.corebanking.service.AccountService;
import com.corebanking.service.AccountServiceImpl;
import com.corebanking.service.TransactionService;
import com.corebanking.service.TransactionServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class RecordEncryptionTest {

    @TempDir
    Path tempDir;

    private byte[] testRecordKey;
    private RecordEncryptionService encryptionService;

    @BeforeEach
    void setUp() {
        testRecordKey = new byte[32];
        new SecureRandom().nextBytes(testRecordKey);
        encryptionService = new RecordEncryptionService(testRecordKey);
        RecordEncryptionService.setActive(encryptionService);
    }

    @AfterEach
    void tearDown() {
        RecordEncryptionService.clearActive();
        DatabaseConnection.clearActiveEncryptionKey();
        if (testRecordKey != null) {
            Arrays.fill(testRecordKey, (byte) 0);
        }
    }

    @Test
    void test1_RoundTripEncryptionAndDecryption() throws Exception {
        String[] samples = {
                "Alice Smith",
                "user.name+test@banking-domain.co.uk",
                "+1-800-555-0199",
                "Special characters: !@#$%^&*()_+{}|:\"<>?~`-=[]\\;',./",
                "Unicode: 现代银行 🏦 🔐 Café München",
                "",
                "A very long customer address and notes field that spans multiple sentences to verify AES-GCM buffer processing."
        };

        for (String sample : samples) {
            String encrypted = encryptionService.encrypt(sample);
            assertNotNull(encrypted);
            assertTrue(encrypted.startsWith("enc:v1:"));
            String decrypted = encryptionService.decrypt(encrypted);
            assertEquals(sample, decrypted, "Decrypted text must match original plaintext");
        }

        // Test null handling
        assertNull(encryptionService.encrypt(null));
        assertNull(encryptionService.decrypt(null));
    }

    @Test
    void test2_NonceFreshnessProducesDistinctCiphertexts() {
        String sensitiveText = "Sensitive Customer Data 12345";
        String enc1 = encryptionService.encrypt(sensitiveText);
        String enc2 = encryptionService.encrypt(sensitiveText);
        String enc3 = encryptionService.encrypt(sensitiveText);

        assertNotEquals(enc1, enc2, "Fresh random nonce must produce unique ciphertext");
        assertNotEquals(enc2, enc3, "Fresh random nonce must produce unique ciphertext");
        assertNotEquals(enc1, enc3, "Fresh random nonce must produce unique ciphertext");

        // Verify all 3 decrypt back to identical plaintext
        assertDoesNotThrow(() -> {
            assertEquals(sensitiveText, encryptionService.decrypt(enc1));
            assertEquals(sensitiveText, encryptionService.decrypt(enc2));
            assertEquals(sensitiveText, encryptionService.decrypt(enc3));
        });
    }

    @Test
    void test3_TamperRejectionFailsSafely() {
        String sensitive = "Classified Account Details";
        String encrypted = encryptionService.encrypt(sensitive);
        String b64 = encrypted.substring(RecordEncryptionService.PREFIX.length());
        byte[] payload = Base64.getDecoder().decode(b64);

        // Tamper with IV (first byte)
        byte[] tamperedIv = payload.clone();
        tamperedIv[0] ^= 0x01;
        String tamperedCiphertext1 = RecordEncryptionService.PREFIX + Base64.getEncoder().encodeToString(tamperedIv);
        assertThrows(GeneralSecurityException.class, () -> encryptionService.decrypt(tamperedCiphertext1));

        // Tamper with ciphertext / tag (last byte)
        byte[] tamperedTag = payload.clone();
        tamperedTag[tamperedTag.length - 1] ^= 0x01;
        String tamperedCiphertext2 = RecordEncryptionService.PREFIX + Base64.getEncoder().encodeToString(tamperedTag);
        assertThrows(GeneralSecurityException.class, () -> encryptionService.decrypt(tamperedCiphertext2));

        // Tamper with invalid Base64
        String invalidBase64 = RecordEncryptionService.PREFIX + "not-a-valid-base64-payload!@#";
        assertThrows(GeneralSecurityException.class, () -> encryptionService.decrypt(invalidBase64));
    }

    @Test
    void test4_TruncatedCiphertextRejection() {
        // Less than 12-byte IV + 16-byte tag (minimum 28 bytes)
        byte[] shortBytes = new byte[20];
        String shortCiphertext = RecordEncryptionService.PREFIX + Base64.getEncoder().encodeToString(shortBytes);
        assertThrows(GeneralSecurityException.class, () -> encryptionService.decrypt(shortCiphertext));
    }

    @Test
    void test5_LegacyPlaintextPassThroughAndIdempotency() throws Exception {
        String legacyText = "John Doe Plaintext";
        // Decrypting non-prefixed string returns as-is
        assertEquals(legacyText, encryptionService.decrypt(legacyText));

        // Encrypting already encrypted string returns as-is (idempotency)
        String encrypted = encryptionService.encrypt(legacyText);
        String doubleEncrypted = encryptionService.encrypt(encrypted);
        assertEquals(encrypted, doubleEncrypted, "Encrypting already-encrypted string must be idempotent");
    }

    @Test
    void test6_DatabaseColumnInspectionVerifiesCiphertextAtRest() throws Exception {
        Path dbPath = tempDir.resolve("inspect_vault.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);
            conn.setAutoCommit(false);

            BankRepository bankRepo = new BankRepository(conn);
            Bank bank = new Bank(1L, "BANK01", "Global Vault Bank", java.time.LocalDateTime.now());
            bankRepo.save(bank);

            AccountRepository accountRepo = new AccountRepository(conn, encryptionService);
            Account account = new Account("ACC-100", "Eleanor Vance", 34, "eleanor@hillhouse.org",
                    "+1-555-0144", bank.getBankId(), AccountType.SAVINGS, new BigDecimal("25000.00"), java.time.LocalDateTime.now());
            accountRepo.save(account);
            conn.commit();

            // Direct raw SQL query on the SQLite database
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT account_id, customer_name, age, email, phone_number, balance, status FROM accounts WHERE account_id = 'ACC-100'")) {
                assertTrue(rs.next());
                assertEquals("ACC-100", rs.getString("account_id"), "Account ID remains plaintext for indexing/keys");
                assertEquals("25000.00", rs.getString("balance"), "Financial balance remains plaintext for decimal math");
                assertEquals("ACTIVE", rs.getString("status"), "Status remains plaintext for check constraints");

                String rawName = rs.getString("customer_name");
                String rawAge = rs.getString("age");
                String rawEmail = rs.getString("email");
                String rawPhone = rs.getString("phone_number");

                // Sensitive fields MUST be stored as encrypted ciphertexts
                assertTrue(rawName.startsWith("enc:v1:"), "customer_name must start with enc:v1:");
                assertTrue(rawAge.startsWith("enc:v1:"), "age must start with enc:v1:");
                assertTrue(rawEmail.startsWith("enc:v1:"), "email must start with enc:v1:");
                assertTrue(rawPhone.startsWith("enc:v1:"), "phone_number must start with enc:v1:");

                // Plaintext strings must NOT be visible anywhere in the raw column data
                assertFalse(rawName.contains("Eleanor"));
                assertFalse(rawAge.contains("34"));
                assertFalse(rawEmail.contains("hillhouse.org"));
                assertFalse(rawPhone.contains("555"));
            }
        }
    }

    @Test
    void test7_RepositoryDecryptionReturnsPlaintext() throws Exception {
        Path dbPath = tempDir.resolve("repo_decrypt.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);
            conn.setAutoCommit(false);

            Bank bank = new Bank(2L, "BNK02", "National Reserve", java.time.LocalDateTime.now());
            new BankRepository(conn).save(bank);
            AccountRepository accountRepo = new AccountRepository(conn, encryptionService);

            Account account = new Account("ACC-200", "Theodora Crain", 28, "theo@arts.studio",
                    "+1-555-0188", bank.getBankId(), AccountType.CURRENT, new BigDecimal("1500.00"), java.time.LocalDateTime.now());
            accountRepo.save(account);
            conn.commit();

            // Fetch through repository
            Account retrieved = accountRepo.findById("ACC-200").orElseThrow();
            assertEquals("Theodora Crain", retrieved.getCustomerName());
            assertEquals(28, retrieved.getAge());
            assertEquals("theo@arts.studio", retrieved.getEmail());
            assertEquals("+1-555-0188", retrieved.getPhoneNumber());
            assertEquals(new BigDecimal("1500.00"), retrieved.getBalance());
        }
    }

    @Test
    void test8_InMemorySearchWithRecordEncryption() throws Exception {
        Path dbPath = tempDir.resolve("search_vault.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);
            conn.setAutoCommit(false);

            BankRepository bankRepo = new BankRepository(conn);
            Bank bank = new Bank(3L, "SRCH", "Search Bank", java.time.LocalDateTime.now());
            bankRepo.save(bank);

            AccountRepository accountRepo = new AccountRepository(conn, encryptionService);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);

            accountService.createAccount("Alice Wonderland", 25, "alice@wonder.land", "+11112222333", bank.getBankId(), AccountType.SAVINGS, new BigDecimal("500.00"));
            accountService.createAccount("Bob Builder", 40, "bob@construction.org", "+13334444555", bank.getBankId(), AccountType.CURRENT, new BigDecimal("800.00"));
            accountService.createAccount("Charlie Chaplin", 55, "charlie@silent.film", "+15556666777", bank.getBankId(), AccountType.SAVINGS, new BigDecimal("1200.00"));
            conn.commit();

            // SQL LIKE search on encrypted columns returns NO MATCH because names are ciphertext
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM accounts WHERE customer_name LIKE '%Wonderland%'")) {
                assertTrue(rs.next());
                assertEquals(0, rs.getInt(1), "Raw SQL LIKE search on ciphertext must find 0 results");
            }

            // In-memory search through AccountService matches decrypted data
            List<Account> searchByName = accountService.searchAccounts("Wonderland");
            assertEquals(1, searchByName.size());
            assertEquals("Alice Wonderland", searchByName.get(0).getCustomerName());

            List<Account> searchByEmail = accountService.searchAccounts("construction.org");
            assertEquals(1, searchByEmail.size());
            assertEquals("Bob Builder", searchByEmail.get(0).getCustomerName());

            List<Account> searchByPhone = accountService.searchAccounts("5556666");
            assertEquals(1, searchByPhone.size());
            assertEquals("Charlie Chaplin", searchByPhone.get(0).getCustomerName());
        }
    }

    @Test
    void test9_BankingOperationsWithRecordEncryption() throws Exception {
        Path dbPath = tempDir.resolve("banking_vault.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);

            BankRepository bankRepo = new BankRepository(conn);
            Bank bank = new Bank(4L, "OPER", "Operations Bank", java.time.LocalDateTime.now());
            bankRepo.save(bank);

            AccountRepository accountRepo = new AccountRepository(conn, encryptionService);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            TransactionService txService = new TransactionServiceImpl(conn, accountService);

            Account acc1 = accountService.createAccount("Sender User", 30, "sender@ops.com", "+10001111222", bank.getBankId(), AccountType.CURRENT, new BigDecimal("1000.00"));
            Account acc2 = accountService.createAccount("Receiver User", 32, "receiver@ops.com", "+10002222333", bank.getBankId(), AccountType.SAVINGS, new BigDecimal("200.00"));

            // 1. Deposit
            txService.deposit(acc1.getAccountId(), new BigDecimal("300.00"), "Deposit Payroll Funds");
            Account acc1AfterDeposit = accountService.findAccount(acc1.getAccountId());
            assertEquals(new BigDecimal("1300.00"), acc1AfterDeposit.getBalance());

            // 2. Withdrawal
            txService.withdraw(acc1.getAccountId(), new BigDecimal("100.00"), "ATM Cash Withdrawal");
            Account acc1AfterWithdraw = accountService.findAccount(acc1.getAccountId());
            assertEquals(new BigDecimal("1200.00"), acc1AfterWithdraw.getBalance());

            // 3. Transfer
            Transaction transferTx = txService.transfer(acc1.getAccountId(), acc2.getAccountId(), new BigDecimal("450.00"), "Monthly Apartment Rent Payment");
            assertEquals(new BigDecimal("750.00"), accountService.findAccount(acc1.getAccountId()).getBalance());
            assertEquals(new BigDecimal("650.00"), accountService.findAccount(acc2.getAccountId()).getBalance());

            // 4. Verify transaction & ledger descriptions are encrypted in DB
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT description FROM transactions WHERE transaction_id = '" + transferTx.getTransactionId() + "'")) {
                assertTrue(rs.next());
                String rawDesc = rs.getString("description");
                assertTrue(rawDesc.startsWith("enc:v1:"), "Transaction description must be encrypted at rest");
                assertFalse(rawDesc.contains("Apartment Rent"));
            }

            // 5. Verify transaction & ledger descriptions are decrypted when read via repositories
            TransactionRepository txRepo = new TransactionRepository(conn, encryptionService);
            Transaction loadedTx = txRepo.findById(transferTx.getTransactionId()).orElseThrow();
            assertEquals("Monthly Apartment Rent Payment", loadedTx.getDescription());

            LedgerRepository ledgerRepo = new LedgerRepository(conn, encryptionService);
            var ledgerEntries = ledgerRepo.findByTransactionId(transferTx.getTransactionId());
            assertEquals(2, ledgerEntries.size());
            for (var entry : ledgerEntries) {
                assertEquals("Monthly Apartment Rent Payment", entry.getDescription());
            }
        }
    }

    @Test
    void test10_IdempotentRecordMigrationWithBackup() throws Exception {
        Path dbPath = tempDir.resolve("plain_to_migrate.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        // Step 1: Insert unencrypted plaintext data
        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);
            conn.setAutoCommit(false);

            new BankRepository(conn).save(new Bank(5L, "MIGR", "Migration Bank", java.time.LocalDateTime.now()));

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO accounts (account_id, customer_name, age, email, phone_number, bank_id, account_type, balance, status, created_at, updated_at) "
                            + "VALUES (?, ?, ?, ?, ?, 1, 'SAVINGS', '500.00', 'ACTIVE', '2026-01-01T00:00:00', '2026-01-01T00:00:00')")) {
                ps.setString(1, "PLAIN-001");
                ps.setString(2, "Legacy Plaintext User");
                ps.setInt(3, 45);
                ps.setString(4, "legacy@bank.com");
                ps.setString(5, "+1-999-0000");
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO transactions (transaction_id, transaction_type, from_account, to_account, amount, status, description, created_at) "
                            + "VALUES (?, 'DEPOSIT', 'SYSTEM-CASH', 'PLAIN-001', '500.00', 'SUCCESS', ?, '2026-01-01T00:00:00')")) {
                ps.setString(1, "TX-PLAIN-1");
                ps.setString(2, "Plaintext initial deposit");
                ps.executeUpdate();
            }

            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO ledger_entries (ledger_entry_id, transaction_id, account_id, entry_type, amount, description, created_at) "
                            + "VALUES (101, 'TX-PLAIN-1', 'PLAIN-001', 'CREDIT', '500.00', ?, '2026-01-01T00:00:00')")) {
                ps.setString(1, "Plaintext initial credit");
                ps.executeUpdate();
            }
            conn.commit();
        }

        // Step 2: Run migration with backup
        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseMigrator.migrateRecordEncryption(dbPath, conn, encryptionService);

            // Verify verified backup file exists
            try (var stream = Files.list(tempDir)) {
                boolean backupExists = stream.anyMatch(p -> p.getFileName().toString().contains("plain_to_migrate.db.backup"));
                assertTrue(backupExists, "A verified backup of the database must be created before migration");
            }

            // Inspect raw database to ensure fields are now encrypted
            try (Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT customer_name, age, email, phone_number FROM accounts WHERE account_id = 'PLAIN-001'")) {
                assertTrue(rs.next());
                assertTrue(rs.getString("customer_name").startsWith("enc:v1:"));
                assertTrue(rs.getString("age").startsWith("enc:v1:"));
                assertTrue(rs.getString("email").startsWith("enc:v1:"));
                assertTrue(rs.getString("phone_number").startsWith("enc:v1:"));
            }

            // Verify reading via repository correctly decrypts
            AccountRepository repo = new AccountRepository(conn, encryptionService);
            Account account = repo.findById("PLAIN-001").orElseThrow();
            assertEquals("Legacy Plaintext User", account.getCustomerName());
            assertEquals(45, account.getAge());
            assertEquals("legacy@bank.com", account.getEmail());
            assertEquals("+1-999-0000", account.getPhoneNumber());

            // Step 3: Run migration AGAIN to verify idempotency (must not double-encrypt)
            DatabaseMigrator.migrateRecordEncryption(dbPath, conn, encryptionService);

            Account accountAfterSecondRun = repo.findById("PLAIN-001").orElseThrow();
            assertEquals("Legacy Plaintext User", accountAfterSecondRun.getCustomerName());
            assertEquals(45, accountAfterSecondRun.getAge());
            assertEquals("legacy@bank.com", accountAfterSecondRun.getEmail());
            assertEquals("+1-999-0000", accountAfterSecondRun.getPhoneNumber());
        }
    }

    @Test
    void test11_DualKeyIndependenceAndDestroyLifecycle() throws Exception {
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] password = "MasterStrongPassword123!".toCharArray();
        VaultKeyManager.VaultKeys keys = keyManager.setupKeys(password);

        assertNotNull(keys.getDatabaseKey());
        assertNotNull(keys.getRecordKey());
        assertEquals(32, keys.getDatabaseKey().length);
        assertEquals(32, keys.getRecordKey().length);

        // Keys MUST be distinct
        assertFalse(Arrays.equals(keys.getDatabaseKey(), keys.getRecordKey()),
                "Database encryption key and Record encryption key must be completely independent");

        // Unlock with correct password
        VaultKeyManager.VaultKeys unlocked = keyManager.unlockKeys(password);
        assertArrayEquals(keys.getDatabaseKey(), unlocked.getDatabaseKey());
        assertArrayEquals(keys.getRecordKey(), unlocked.getRecordKey());

        // Incorrect password fails safely
        char[] wrongPassword = "WrongPassword999!".toCharArray();
        assertThrows(GeneralSecurityException.class, () -> keyManager.unlockKeys(wrongPassword));

        // Tampered metadata fails safely and does NOT recreate
        PropertiesMetadataTamper(metaPath);
        assertThrows(GeneralSecurityException.class, () -> keyManager.unlockKeys(password));

        // Test destroy lifecycle on RecordEncryptionService
        RecordEncryptionService service = new RecordEncryptionService(unlocked.getRecordKey());
        String encrypted = service.encrypt("Confidential");
        assertEquals("Confidential", service.decrypt(encrypted));

        service.destroy();
        assertTrue(service.isDestroyed());
        assertThrows(IllegalStateException.class, () -> service.encrypt("New Data"));
        assertThrows(IllegalStateException.class, () -> service.decrypt(encrypted));

        // Clear keys
        keys.clear();
        unlocked.clear();
    }

    private void PropertiesMetadataTamper(Path metaPath) throws IOException {
        String content = Files.readString(metaPath);
        // Corrupt the record wrappedKey
        String corrupted = content.replace("record.wrappedKey=", "record.wrappedKey=ff00");
        Files.writeString(metaPath, corrupted);
    }
}
