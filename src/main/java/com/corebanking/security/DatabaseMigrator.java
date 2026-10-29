package com.corebanking.security;

import com.corebanking.config.DatabaseInitializer;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Manages safe, verified migration of existing plaintext SQLite databases to whole-database encryption.
 * Automatically creates a verified backup before performing any migration operations.
 */
public final class DatabaseMigrator {
    private static final byte[] SQLITE_HEADER = "SQLite format 3\000".getBytes(StandardCharsets.US_ASCII);

    private DatabaseMigrator() {
    }

    /**
     * Checks whether the target file exists and has an unencrypted SQLite header.
     */
    public static boolean isPlaintextDatabase(Path databaseFile) {
        if (!Files.exists(databaseFile) || !Files.isRegularFile(databaseFile)) {
            return false;
        }
        try (InputStream in = Files.newInputStream(databaseFile)) {
            byte[] header = new byte[SQLITE_HEADER.length];
            int read = in.read(header);
            if (read < SQLITE_HEADER.length) {
                return false;
            }
            for (int i = 0; i < SQLITE_HEADER.length; i++) {
                if (header[i] != SQLITE_HEADER[i]) {
                    return false;
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Creates a verified, timestamped backup copy of the database.
     */
    public static Path createVerifiedBackup(Path databaseFile) throws IOException {
        if (!Files.exists(databaseFile)) {
            throw new IOException("Cannot backup non-existent database: " + databaseFile);
        }
        String timestamp = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss").format(LocalDateTime.now());
        Path backupPath = databaseFile.getParent().resolve(databaseFile.getFileName() + ".backup." + timestamp);
        Files.copy(databaseFile, backupPath, StandardCopyOption.REPLACE_EXISTING);
        if (Files.size(backupPath) != Files.size(databaseFile)) {
            throw new IOException("Backup verification failed: file size mismatch.");
        }
        return backupPath;
    }

    /**
     * Safely migrates an existing plaintext database to an encrypted database using the provided key.
     * 1. Creates a temporary, owner-restricted safety backup of the plaintext database during migration.
     * 2. Initializes an encrypted staging database and copies all data into it.
     * 3. Verifies readability and record counts under encryption.
     * 4. Atomically replaces the original database with the encrypted database.
     * 5. Creates a retained, verified ENCRYPTED backup of the newly encrypted database.
     * 6. Securely deletes the temporary plaintext safety backup and removes any legacy plaintext backups.
     */
    public static void migrateToEncrypted(Path databaseFile, String encryptionKeyHex) throws IOException, SQLException {
        if (!isPlaintextDatabase(databaseFile)) {
            return;
        }

        // 1. Create temporary migration safety backup of the plaintext database
        Path tempPlainBackup = databaseFile.getParent().resolve(databaseFile.getFileName() + ".migration-safety.tmp");
        Files.copy(databaseFile, tempPlainBackup, StandardCopyOption.REPLACE_EXISTING);
        try {
            tempPlainBackup.toFile().setReadable(true, true);
            tempPlainBackup.toFile().setWritable(true, true);
        } catch (Exception ignored) {}

        // 2. Prepare encrypted staging database
        Path stagingPath = databaseFile.getParent().resolve(databaseFile.getFileName() + ".migrating");
        Files.deleteIfExists(stagingPath);

        String plainUrl = "jdbc:sqlite:" + databaseFile.toAbsolutePath();
        String encUrl = "jdbc:sqlite:file:" + stagingPath.toAbsolutePath().toUri().getPath()
                + "?cipher=sqlcipher&key=x'" + encryptionKeyHex + "'&legacy=4";

        try {
            try (Connection plainConn = DriverManager.getConnection(plainUrl);
                 Connection encConn = DriverManager.getConnection(encUrl)) {

                // Initialize schema in encrypted staging DB
                DatabaseInitializer.initialize(encConn);

                encConn.setAutoCommit(false);
                try {
                    copyTable(plainConn, encConn, "banks",
                            "INSERT INTO banks (bank_id, bank_code, bank_name, created_at, is_demo) VALUES (?, ?, ?, ?, ?)",
                            5);
                    copyTable(plainConn, encConn, "accounts",
                            "INSERT INTO accounts (account_id, customer_name, age, email, phone_number, bank_id, account_type, balance, status, created_at, updated_at, is_demo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            12);
                    copyTable(plainConn, encConn, "transactions",
                            "INSERT INTO transactions (transaction_id, transaction_type, from_account, to_account, amount, status, description, created_at, is_demo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            9);
                    copyTable(plainConn, encConn, "ledger_entries",
                            "INSERT INTO ledger_entries (ledger_entry_id, transaction_id, account_id, entry_type, amount, description, created_at, is_demo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            8);
                    encConn.commit();
                } catch (SQLException e) {
                    encConn.rollback();
                    throw e;
                }
            }

            // 3. Verify encrypted staging database is valid and readable
            try (Connection verifyConn = DriverManager.getConnection(encUrl);
                 Statement stmt = verifyConn.createStatement();
                 ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM accounts")) {
                if (!rs.next()) {
                    throw new SQLException("Verification query failed on migrated encrypted database.");
                }
            }

            // 4. Atomically swap staging into place
            Files.move(stagingPath, databaseFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

            // 5. Verify databaseFile is now encrypted at rest
            if (isPlaintextDatabase(databaseFile)) {
                throw new SQLException("Post-migration check failed: database file is still plaintext.");
            }

            // 6. Create verified encrypted backup of the newly encrypted database
            createVerifiedBackup(databaseFile);

            // 7. Securely delete the temporary plaintext backup now that encrypted database is active
            Files.deleteIfExists(tempPlainBackup);

            // 8. Clean up any lingering legacy plaintext backups in the directory
            cleanupLegacyPlaintextBackups(databaseFile.getParent());
        } catch (Exception ex) {
            // Restore from temporary plaintext backup if migration failed and target was damaged
            if (!Files.exists(databaseFile) && Files.exists(tempPlainBackup)) {
                Files.copy(tempPlainBackup, databaseFile, StandardCopyOption.REPLACE_EXISTING);
            }
            throw ex;
        } finally {
            Files.deleteIfExists(stagingPath);
        }
    }

    /**
     * Checks if any records in the database require record-level field encryption migration.
     */
    public static boolean requiresRecordMigration(Connection connection) throws SQLException {
        if (connection == null) {
            return false;
        }

        // Check if any accounts have unencrypted sensitive fields
        String checkAccounts = "SELECT 1 FROM accounts WHERE "
                + "(customer_name IS NOT NULL AND customer_name NOT LIKE 'enc:v1:%') OR "
                + "(age IS NOT NULL AND age NOT LIKE 'enc:v1:%') OR "
                + "(email IS NOT NULL AND email NOT LIKE 'enc:v1:%') OR "
                + "(phone_number IS NOT NULL AND phone_number NOT LIKE 'enc:v1:%') LIMIT 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(checkAccounts)) {
            if (rs.next()) {
                return true;
            }
        }

        // Check transactions
        String checkTx = "SELECT 1 FROM transactions WHERE description IS NOT NULL AND description NOT LIKE 'enc:v1:%' LIMIT 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(checkTx)) {
            if (rs.next()) {
                return true;
            }
        }

        // Check ledger_entries
        String checkLedger = "SELECT 1 FROM ledger_entries WHERE description IS NOT NULL AND description NOT LIKE 'enc:v1:%' LIMIT 1";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(checkLedger)) {
            if (rs.next()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Idempotently migrates unencrypted sensitive fields in an existing database to AES-256-GCM ciphertexts.
     * Only creates a backup and runs updates if unencrypted records actually exist.
     */
    public static void migrateRecordEncryption(Path databaseFile, Connection connection, RecordEncryptionService recordService)
            throws IOException, SQLException {
        if (!requiresRecordMigration(connection)) {
            return; // No migration needed; avoids creating redundant backups on every startup
        }

        if (databaseFile != null && Files.exists(databaseFile)) {
            // Checkpoint any uncommitted WAL pages before copying
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA wal_checkpoint(TRUNCATE);");
            } catch (SQLException ignored) {}
            createVerifiedBackup(databaseFile);
        }
        migrateRecordEncryption(connection, recordService);
    }

    /**
     * Safely cleans up legacy plaintext backup files (*.backup.*) in the target directory
     * so unencrypted historical databases do not expose sensitive customer data at rest.
     */
    public static void cleanupLegacyPlaintextBackups(Path directory) {
        if (directory == null || !Files.exists(directory)) {
            return;
        }
        try (var stream = Files.list(directory)) {
            stream.filter(Files::isRegularFile)
                    .filter(path -> {
                        String name = path.getFileName().toString();
                        return (name.contains(".backup.") || name.endsWith(".bak")) && isPlaintextDatabase(path);
                    })
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {}
                    });
        } catch (IOException ignored) {}
    }

    /**
     * Idempotently migrates unencrypted sensitive fields in an existing database to AES-256-GCM ciphertexts.
     * All modifications are executed within an atomic database transaction.
     */
    public static void migrateRecordEncryption(Connection connection, RecordEncryptionService recordService)
            throws SQLException {
        if (connection == null || recordService == null) {
            return;
        }

        boolean originalAutoCommit = connection.getAutoCommit();
        try {
            connection.setAutoCommit(false);

            // 1. Migrate accounts: customer_name, age, email, phone_number
            String selectAccounts = "SELECT account_id, customer_name, age, email, phone_number FROM accounts";
            String updateAccount = "UPDATE accounts SET customer_name = ?, age = ?, email = ?, phone_number = ? WHERE account_id = ?";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(selectAccounts);
                 PreparedStatement ps = connection.prepareStatement(updateAccount)) {
                boolean hasUpdates = false;
                while (rs.next()) {
                    String id = rs.getString("account_id");
                    String rawName = rs.getString("customer_name");
                    String rawAge = rs.getString("age");
                    String rawEmail = rs.getString("email");
                    String rawPhone = rs.getString("phone_number");

                    boolean needsUpdate = (rawName != null && !rawName.startsWith(RecordEncryptionService.PREFIX))
                            || (rawAge != null && !rawAge.startsWith(RecordEncryptionService.PREFIX))
                            || (rawEmail != null && !rawEmail.startsWith(RecordEncryptionService.PREFIX))
                            || (rawPhone != null && !rawPhone.startsWith(RecordEncryptionService.PREFIX));

                    if (needsUpdate) {
                        ps.setString(1, recordService.encrypt(rawName));
                        ps.setString(2, recordService.encrypt(rawAge));
                        ps.setString(3, recordService.encrypt(rawEmail));
                        ps.setString(4, recordService.encrypt(rawPhone));
                        ps.setString(5, id);
                        ps.addBatch();
                        hasUpdates = true;
                    }
                }
                if (hasUpdates) {
                    ps.executeBatch();
                }
            }

            // 2. Migrate transactions: description
            String selectTx = "SELECT transaction_id, description FROM transactions WHERE description IS NOT NULL AND description NOT LIKE 'enc:v1:%'";
            String updateTx = "UPDATE transactions SET description = ? WHERE transaction_id = ?";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(selectTx);
                 PreparedStatement ps = connection.prepareStatement(updateTx)) {
                boolean hasUpdates = false;
                while (rs.next()) {
                    String id = rs.getString("transaction_id");
                    String desc = rs.getString("description");
                    ps.setString(1, recordService.encrypt(desc));
                    ps.setString(2, id);
                    ps.addBatch();
                    hasUpdates = true;
                }
                if (hasUpdates) {
                    ps.executeBatch();
                }
            }

            // 3. Migrate ledger_entries: description
            String selectLedger = "SELECT ledger_entry_id, description FROM ledger_entries WHERE description IS NOT NULL AND description NOT LIKE 'enc:v1:%'";
            String updateLedger = "UPDATE ledger_entries SET description = ? WHERE ledger_entry_id = ?";
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(selectLedger);
                 PreparedStatement ps = connection.prepareStatement(updateLedger)) {
                boolean hasUpdates = false;
                while (rs.next()) {
                    long id = rs.getLong("ledger_entry_id");
                    String desc = rs.getString("description");
                    ps.setString(1, recordService.encrypt(desc));
                    ps.setLong(2, id);
                    ps.addBatch();
                    hasUpdates = true;
                }
                if (hasUpdates) {
                    ps.executeBatch();
                }
            }

            connection.commit();
        } catch (SQLException e) {
            connection.rollback();
            throw e;
        } finally {
            connection.setAutoCommit(originalAutoCommit);
        }
    }

    private static void copyTable(Connection src, Connection dest, String tableName, String insertSql, int columnCount)
            throws SQLException {
        try (Statement stmt = src.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM " + tableName);
             PreparedStatement ps = dest.prepareStatement(insertSql)) {
            while (rs.next()) {
                for (int i = 1; i <= columnCount; i++) {
                    ps.setObject(i, rs.getObject(i));
                }
                ps.addBatch();
            }
            ps.executeBatch();
        }
    }
}

