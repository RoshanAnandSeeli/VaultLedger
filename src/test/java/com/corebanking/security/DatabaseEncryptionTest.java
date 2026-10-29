package com.corebanking.security;

import com.corebanking.config.DatabaseConnection;
import com.corebanking.config.DatabaseInitializer;
import com.corebanking.enums.AccountType;
import com.corebanking.enums.LedgerEntryType;
import com.corebanking.model.Account;
import com.corebanking.model.Bank;
import com.corebanking.model.Transaction;
import com.corebanking.repository.AccountRepository;
import com.corebanking.repository.BankRepository;
import com.corebanking.repository.LedgerRepository;
import com.corebanking.repository.TransactionRepository;
import com.corebanking.service.AccountService;
import com.corebanking.service.AccountServiceImpl;
import com.corebanking.service.LedgerServiceImpl;
import com.corebanking.service.TransactionService;
import com.corebanking.service.TransactionServiceImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.AEADBadTagException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class DatabaseEncryptionTest {

    @TempDir
    Path tempDir;

    @AfterEach
    void tearDown() {
        DatabaseConnection.clearActiveEncryptionKey();
    }

    @Test
    void test1_SuccessfulDatabaseUnlock() throws Exception {
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        assertFalse(keyManager.isInitialized());

        char[] password = "SecureVaultPassword123!".toCharArray();
        byte[] createdKey = keyManager.setupMasterKey(password);
        assertTrue(keyManager.isInitialized());
        assertNotNull(createdKey);
        assertEquals(32, createdKey.length);

        byte[] unlockedKey = keyManager.unlock(password);
        assertArrayEquals(createdKey, unlockedKey);

        VaultKeyManager.clear(createdKey);
        VaultKeyManager.clear(unlockedKey);
    }

    @Test
    void test2_IncorrectCredentialRejection() throws Exception {
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] password = "CorrectPassword123!".toCharArray();
        keyManager.setupMasterKey(password);

        char[] wrongPassword = "WrongPassword456!".toCharArray();
        assertThrows(GeneralSecurityException.class, () -> keyManager.unlock(wrongPassword));
    }

    @Test
    void test3_DatabaseFileConfidentialityAtRest() throws Exception {
        Path dbPath = tempDir.resolve("encrypted_audit.db");
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] password = "SecretMasterPassword2026!".toCharArray();
        byte[] rawKey = keyManager.setupMasterKey(password);
        String hexKey = HexFormat.of().formatHex(rawKey);

        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            DatabaseInitializer.initialize(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "TEST", "Confidential Bank", LocalDateTime.now()));
        }

        // Verify that the on-disk file header is completely scrambled and NOT plaintext "SQLite format 3"
        byte[] header = new byte[16];
        try (InputStream in = Files.newInputStream(dbPath)) {
            in.read(header);
        }
        String headerStr = new String(header, StandardCharsets.US_ASCII);
        assertFalse(headerStr.startsWith("SQLite format 3"), "Encrypted database must not expose SQLite magic header!");

        // Verify that attempting to open directly with standard unencrypted driver fails immediately
        String plainUrl = "jdbc:sqlite:" + dbPath.toAbsolutePath();
        assertThrows(SQLException.class, () -> {
            try (Connection conn = DriverManager.getConnection(plainUrl);
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT count(*) FROM banks")) {
                rs.next();
            }
        });
    }

    @Test
    void test4_PersistenceAcrossApplicationRestarts() throws Exception {
        Path dbPath = tempDir.resolve("restart_test.db");
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] password = "PersistentPassword789#".toCharArray();
        byte[] rawKey = keyManager.setupMasterKey(password);
        String hexKey = HexFormat.of().formatHex(rawKey);

        // Session 1: Create account and deposit money
        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            DatabaseInitializer.initialize(conn);
            AccountRepository accountRepo = new AccountRepository(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "NSB", "Northstar Bank", LocalDateTime.now()));

            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            TransactionService txnService = new TransactionServiceImpl(conn, accountService);

            accountService.createAccount("ACC-SAVE", "Alice", 1L, AccountType.SAVINGS, new BigDecimal("1000.00"));
            txnService.deposit("ACC-SAVE", new BigDecimal("500.00"), "Initial Deposit");
        }

        // Simulate application restart: clear active session key
        DatabaseConnection.clearActiveEncryptionKey();
        assertNull(DatabaseConnection.getActiveEncryptionKeyHex());

        // Session 2: Unlock with master password and verify balance
        byte[] unlockedKey = keyManager.unlock(password);
        String restoredHexKey = HexFormat.of().formatHex(unlockedKey);
        DatabaseConnection.setActiveEncryptionKeyHex(restoredHexKey);

        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            AccountRepository accountRepo = new AccountRepository(conn);
            var account = accountRepo.findById("ACC-SAVE").orElseThrow();
            assertEquals(new BigDecimal("1500.00"), account.getBalance());
        }
    }

    @Test
    void test5_ExistingDataPreservedThroughMigration() throws Exception {
        Path plainDb = tempDir.resolve("existing_plain.db");
        // 1. Create a legacy unencrypted database with initial accounts and ledger
        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + plainDb.toAbsolutePath())) {
            DatabaseInitializer.initialize(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "LEGACY", "Legacy Bank", LocalDateTime.now()));
            AccountRepository accountRepo = new AccountRepository(conn);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            TransactionService txnService = new TransactionServiceImpl(conn, accountService);

            accountService.createAccount("ACC-LEGACY", "Bob Legacy", 1L, AccountType.CURRENT, new BigDecimal("2500.00"));
            txnService.deposit("ACC-LEGACY", new BigDecimal("750.00"), "Deposit pre-migration");
        }

        assertTrue(DatabaseMigrator.isPlaintextDatabase(plainDb));

        // 2. Perform safe migration
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("MigrationSecret123!".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseMigrator.migrateToEncrypted(plainDb, hexKey);

        // Verify original file is now encrypted
        assertFalse(DatabaseMigrator.isPlaintextDatabase(plainDb));

        // Verify backup file exists and is encrypted at rest
        Path backupFile = Files.list(tempDir)
                .filter(p -> p.getFileName().toString().contains("existing_plain.db.backup."))
                .findFirst()
                .orElseThrow();
        assertFalse(DatabaseMigrator.isPlaintextDatabase(backupFile), "Retained backup must be encrypted at rest!");

        // Plaintext SQLite driver cannot open the encrypted backup
        assertThrows(SQLException.class, () -> {
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + backupFile.toAbsolutePath());
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT count(*) FROM accounts")) {
                rs.next();
            }
        });

        // 3. Verify data readability under encrypted connection
        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(plainDb)) {
            AccountRepository accountRepo = new AccountRepository(conn);
            var account = accountRepo.findById("ACC-LEGACY").orElseThrow();
            assertEquals(new BigDecimal("3250.00"), account.getBalance());

            TransactionRepository txnRepo = new TransactionRepository(conn);
            assertEquals(1, txnRepo.findAll().size());

            LedgerRepository ledgerRepo = new LedgerRepository(conn);
            assertEquals(2, ledgerRepo.findAll().size());
        }
    }

    @Test
    void test6_TamperedOrInvalidEncryptedDataRejectedSafely() throws Exception {
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] password = "ValidPassword123!".toCharArray();
        keyManager.setupMasterKey(password);

        // Tamper with the wrappedKey bytes in the metadata file
        String content = Files.readString(metaPath);
        // Flip one character in the hex wrappedKey
        String tampered = content.replace("wrappedKey=", "wrappedKey=ff");
        Files.writeString(metaPath, tampered);

        // Decryption must fail via AEAD tag authentication
        assertThrows(GeneralSecurityException.class, () -> keyManager.unlock(password));
    }

    @Test
    void test7_FailedTransfersStillRollBackOnEncryptedDatabase() throws Exception {
        Path dbPath = tempDir.resolve("enc_rollback.db");
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("PasswordForRollback#".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            DatabaseInitializer.initialize(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "RB", "Rollback Bank", LocalDateTime.now()));
            AccountRepository accountRepo = new AccountRepository(conn);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            TransactionService txnService = new TransactionServiceImpl(conn, accountService);

            accountService.createAccount("ACC-SENDER", "Sender", 1L, AccountType.SAVINGS, new BigDecimal("1000.00"));
            accountService.createAccount("ACC-RECEIVER", "Receiver", 1L, AccountType.SAVINGS, new BigDecimal("500.00"));

            // Force a database failure using a trigger
            try (var statement = conn.createStatement()) {
                statement.execute("CREATE TRIGGER fail_transfer BEFORE INSERT ON transactions "
                        + "WHEN NEW.description = 'fail_me' "
                        + "BEGIN SELECT RAISE(ABORT, 'forced abort'); END");
            }

            assertThrows(RuntimeException.class, () ->
                    txnService.transfer("ACC-SENDER", "ACC-RECEIVER", new BigDecimal("200.00"), "fail_me"));

            // Balances must remain unchanged
            assertEquals(new BigDecimal("1000.00"), accountRepo.findById("ACC-SENDER").orElseThrow().getBalance());
            assertEquals(new BigDecimal("500.00"), accountRepo.findById("ACC-RECEIVER").orElseThrow().getBalance());

            // No transaction or ledger entry created
            TransactionRepository txnRepo = new TransactionRepository(conn);
            assertTrue(txnRepo.findAll().isEmpty());
            LedgerRepository ledgerRepo = new LedgerRepository(conn);
            assertTrue(ledgerRepo.findAll().isEmpty());
        }
    }

    @Test
    void test8_ConcurrentTransfersPreserveInvariantsOnEncryptedDatabase() throws Exception {
        Path dbPath = tempDir.resolve("enc_concurrency.db");
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("ConcurrencyPassword999!".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            DatabaseInitializer.initialize(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "CB", "Concurrent Bank", LocalDateTime.now()));
            AccountRepository accountRepo = new AccountRepository(conn);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            accountService.createAccount("ACC-1", "User 1", 1L, AccountType.SAVINGS, new BigDecimal("10000.00"));
            accountService.createAccount("ACC-2", "User 2", 1L, AccountType.SAVINGS, new BigDecimal("10000.00"));
        }

        int count = 20;
        ExecutorService executor = Executors.newFixedThreadPool(count);
        CountDownLatch ready = new CountDownLatch(count);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Transaction>> futures = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            final int index = i;
            futures.add(executor.submit(() -> {
                ready.countDown();
                start.await();
                try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
                    AccountService accService = new AccountServiceImpl(new AccountRepository(conn), new BankRepository(conn));
                    TransactionService txnService = new TransactionServiceImpl(conn, accService);
                    String from = (index % 2 == 0) ? "ACC-1" : "ACC-2";
                    String to = (index % 2 == 0) ? "ACC-2" : "ACC-1";
                    return txnService.transfer(from, to, new BigDecimal("100.00"), "concurrent-encrypted-transfer");
                }
            }));
        }

        assertTrue(ready.await(10, TimeUnit.SECONDS));
        start.countDown();

        for (var f : futures) {
            assertNotNull(f.get(20, TimeUnit.SECONDS));
        }
        executor.shutdownNow();

        // Verify conservation of money and balanced ledger entries
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            AccountRepository accountRepo = new AccountRepository(conn);
            BigDecimal totalBalance = accountRepo.findById("ACC-1").orElseThrow().getBalance()
                    .add(accountRepo.findById("ACC-2").orElseThrow().getBalance());
            assertEquals(new BigDecimal("20000.00"), totalBalance);

            LedgerRepository ledgerRepo = new LedgerRepository(conn);
            var entries = ledgerRepo.findAll();
            assertEquals(count * 2, entries.size());

            BigDecimal debits = entries.stream()
                    .filter(e -> e.getEntryType() == LedgerEntryType.DEBIT)
                    .map(e -> e.getAmount())
                    .reduce(BigDecimal.ZERO, BigDecimal::add);
            BigDecimal credits = entries.stream()
                    .filter(e -> e.getEntryType() == LedgerEntryType.CREDIT)
                    .map(e -> e.getAmount())
                    .reduce(BigDecimal.ZERO, BigDecimal::add);
            assertEquals(debits, credits);
            assertEquals(new BigDecimal(count * 100).setScale(2), debits);
        }
    }

    @Test
    void test9_LogoutClosesConnectionAndClearsState() throws Exception {
        Path dbPath = tempDir.resolve("logout_test.db");
        DatabaseConnection.setActiveEncryptionKeyHex("deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567");
        Connection conn = DatabaseConnection.openConnection(dbPath);
        assertFalse(conn.isClosed());

        // Simulate logout
        conn.close();
        DatabaseConnection.clearActiveEncryptionKey();

        assertTrue(conn.isClosed());
        assertNull(DatabaseConnection.getActiveEncryptionKeyHex());
    }

    @Test
    void test10_ExistingDatabaseFilesNeverSilentlyOverwrittenOnUnlockFailure() throws Exception {
        Path dbPath = tempDir.resolve("protected_vault.db");
        Path metaPath = tempDir.resolve("vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("CorrectPassphrase999!".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(dbPath)) {
            DatabaseInitializer.initialize(conn);
            AccountRepository accountRepo = new AccountRepository(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "PROT", "Protected Bank", LocalDateTime.now()));
            new AccountServiceImpl(accountRepo, bankRepo).createAccount("ACC-PROT", "Valuable Customer", 1L, AccountType.SAVINGS, new BigDecimal("50000.00"));
        }

        long originalSize = Files.size(dbPath);
        assertTrue(originalSize > 0);

        // Attempt unlock with wrong password
        assertThrows(GeneralSecurityException.class, () -> keyManager.unlock("WrongPassword!".toCharArray()));

        // Confirm database file was NOT modified, truncated, or recreated
        assertEquals(originalSize, Files.size(dbPath), "Existing database file must never be truncated or overwritten after failed authentication!");
    }

    @Test
    void test11_RetainedBackupsAreEncryptedAndRejectPlaintextAccess() throws Exception {
        Path plainDb = tempDir.resolve("customer_plain.db");
        String plainUrl = "jdbc:sqlite:" + plainDb.toAbsolutePath();

        try (Connection conn = DriverManager.getConnection(plainUrl)) {
            DatabaseInitializer.initialize(conn);
            conn.setAutoCommit(false);
            new BankRepository(conn).save(new Bank(1L, "TEST", "Plaintext Bank", LocalDateTime.now()));
            AccountRepository accountRepo = new AccountRepository(conn);
            AccountService accountService = new AccountServiceImpl(accountRepo, new BankRepository(conn));
            accountService.createAccount("ACC-SECRET", "Secret Customer", 1L, AccountType.SAVINGS, new BigDecimal("10000.00"));
            conn.commit();
        }

        assertTrue(DatabaseMigrator.isPlaintextDatabase(plainDb));

        // Migrate to encrypted database
        Path metaPath = tempDir.resolve("vault-key-backup.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("SuperStrongPassphrase123!".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseMigrator.migrateToEncrypted(plainDb, hexKey);

        // Active DB must be encrypted
        assertFalse(DatabaseMigrator.isPlaintextDatabase(plainDb));

        // Temporary plaintext safety backup must NOT exist
        Path tempPlain = plainDb.getParent().resolve(plainDb.getFileName() + ".migration-safety.tmp");
        assertFalse(Files.exists(tempPlain), "Temporary plaintext safety backup must be deleted after successful migration");

        // Retained backup MUST be encrypted at rest
        Path backupFile = Files.list(tempDir)
                .filter(p -> p.getFileName().toString().contains("customer_plain.db.backup."))
                .findFirst()
                .orElseThrow();
        assertFalse(DatabaseMigrator.isPlaintextDatabase(backupFile), "Retained backup must be encrypted at rest!");

        // Querying retained backup as ordinary unencrypted SQLite fails
        assertThrows(SQLException.class, () -> {
            try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + backupFile.toAbsolutePath());
                 Statement stmt = conn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT * FROM accounts")) {
                rs.next();
            }
        });
    }

    @Test
    void test12_EncryptedBackupCanBeRestoredAndUnlocked() throws Exception {
        Path originalDb = tempDir.resolve("restore_source.db");
        Path metaPath = tempDir.resolve("vault-restore.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);
        byte[] key = keyManager.setupMasterKey("RestorePassphrase456!".toCharArray());
        String hexKey = HexFormat.of().formatHex(key);

        DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
        try (Connection conn = DatabaseConnection.openConnection(originalDb)) {
            DatabaseInitializer.initialize(conn);
            BankRepository bankRepo = new BankRepository(conn);
            bankRepo.save(new Bank(1L, "REST", "Restore Bank", LocalDateTime.now()));
            AccountRepository accountRepo = new AccountRepository(conn);
            AccountService accountService = new AccountServiceImpl(accountRepo, bankRepo);
            accountService.createAccount("ACC-RESTORE", "Restore User", 1L, AccountType.CURRENT, new BigDecimal("777.00"));
        }

        // Create verified encrypted backup
        Path backupFile = DatabaseMigrator.createVerifiedBackup(originalDb);
        assertFalse(DatabaseMigrator.isPlaintextDatabase(backupFile), "Backup must be encrypted!");

        // Simulate disaster recovery: delete original database and restore from backup file
        Files.delete(originalDb);
        assertFalse(Files.exists(originalDb));

        Path restoredDb = tempDir.resolve("restored_active.db");
        Files.copy(backupFile, restoredDb);

        // Unlock restored database using the supported encrypted workflow
        try (Connection restoredConn = DatabaseConnection.openConnection(restoredDb)) {
            AccountRepository repo = new AccountRepository(restoredConn);
            var account = repo.findById("ACC-RESTORE").orElseThrow();
            assertEquals("Restore User", account.getCustomerName());
            assertEquals(new BigDecimal("777.00"), account.getBalance());
        }
    }

    @Test
    void test13_RecordMigrationDoesNotCreateRedundantBackupsOnSubsequentLaunches() throws Exception {
        Path dbPath = tempDir.resolve("no_duplicate_backups.db");
        String url = "jdbc:sqlite:" + dbPath.toAbsolutePath();

        byte[] recordKey = new byte[32];
        RecordEncryptionService recordService = new RecordEncryptionService(recordKey);

        try (Connection conn = DriverManager.getConnection(url)) {
            DatabaseInitializer.initialize(conn);
            Bank bank = new Bank(1L, "NOBKP", "No Backup Bank", LocalDateTime.now());
            new BankRepository(conn).save(bank);

            AccountRepository repo = new AccountRepository(conn, recordService);
            Account account = new Account("ACC-ENC-1", "Pre-encrypted User", 30, "user@bank.com",
                    "+1-555-0100", 1L, AccountType.SAVINGS, new BigDecimal("100.00"), LocalDateTime.now());
            repo.save(account);

            // Record migration should detect no plaintext records are present
            assertFalse(DatabaseMigrator.requiresRecordMigration(conn));

            // Simulating multiple application launches (e.g. 5 restarts)
            for (int i = 0; i < 5; i++) {
                DatabaseMigrator.migrateRecordEncryption(dbPath, conn, recordService);
            }

            // Zero backup files should have been created!
            long backupFiles = Files.list(tempDir)
                    .filter(p -> p.getFileName().toString().contains("no_duplicate_backups.db.backup."))
                    .count();
            assertEquals(0, backupFiles, "No backup files should be created when no migration is required!");
        }
    }

    @Test
    void test14_VaultKeyMetaDoesNotPersistPlaintextSecrets() throws Exception {
        Path metaPath = tempDir.resolve("audit_vault-key.meta");
        VaultKeyManager keyManager = new VaultKeyManager(metaPath);

        char[] masterPass = "TopSecretMasterPassphrase2026!".toCharArray();
        VaultKeyManager.VaultKeys keys = keyManager.setupKeys(masterPass);

        // Read the saved metadata file directly as text
        String metaText = Files.readString(metaPath);
        java.util.Properties props = new java.util.Properties();
        try (var in = Files.newInputStream(metaPath)) {
            props.load(in);
        }

        // 1. Password or passphrase must NEVER be stored
        assertFalse(metaText.contains("TopSecretMasterPassphrase2026!"), "Plaintext password must NEVER appear in vault-key.meta!");
        assertFalse(metaText.toLowerCase().contains("password"), "Metadata keys must not contain password fields!");

        // 2. Iterations must meet security threshold
        int iterations = Integer.parseInt(props.getProperty("iterations"));
        assertTrue(iterations >= 100_000, "PBKDF2 iteration count must be at least 100,000");

        // 3. Salts must be 16 bytes (32 hex characters)
        String dbSalt = props.getProperty("db.salt");
        String recSalt = props.getProperty("record.salt");
        assertNotNull(dbSalt);
        assertNotNull(recSalt);
        assertEquals(32, dbSalt.length(), "DB salt must be 16 bytes (32 hex chars)");
        assertEquals(32, recSalt.length(), "Record salt must be 16 bytes (32 hex chars)");
        assertNotEquals(dbSalt, recSalt, "DB and Record salts must be distinct");

        // 4. Nonces/IVs must be 12 bytes (24 hex characters)
        String dbIv = props.getProperty("db.iv");
        String recIv = props.getProperty("record.iv");
        assertNotNull(dbIv);
        assertNotNull(recIv);
        assertEquals(24, dbIv.length(), "DB IV must be 12 bytes (24 hex chars)");
        assertEquals(24, recIv.length(), "Record IV must be 12 bytes (24 hex chars)");
        assertNotEquals(dbIv, recIv, "DB and Record IVs must be distinct");

        // 5. Wrapped keys must be 48 bytes (96 hex characters = 32 bytes AES key + 16 bytes GCM tag)
        String dbWrappedKey = props.getProperty("db.wrappedKey");
        String recWrappedKey = props.getProperty("record.wrappedKey");
        assertNotNull(dbWrappedKey);
        assertNotNull(recWrappedKey);
        assertEquals(96, dbWrappedKey.length(), "Wrapped DB key must be 48 bytes (96 hex chars)");
        assertEquals(96, recWrappedKey.length(), "Wrapped Record key must be 48 bytes (96 hex chars)");
        assertNotEquals(dbWrappedKey, recWrappedKey, "Wrapped DB and Record keys must be distinct");

        // 6. Plaintext unwrapped keys must NEVER match wrapped ciphertext
        String rawDbHex = HexFormat.of().formatHex(keys.getDatabaseKey());
        String rawRecHex = HexFormat.of().formatHex(keys.getRecordKey());
        assertFalse(metaText.contains(rawDbHex), "Plaintext DB key must NEVER appear in vault-key.meta!");
        assertFalse(metaText.contains(rawRecHex), "Plaintext Record key must NEVER appear in vault-key.meta!");

        keys.clear();
    }
}

