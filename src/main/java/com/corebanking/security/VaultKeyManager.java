package com.corebanking.security;

import com.corebanking.config.AppConfig;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;

/**
 * Manages the dual-key lifecycle for VaultLedger:
 * 1. Database Encryption Key: 256-bit key for SQLite3MultipleCiphers whole-database page encryption.
 * 2. Record Encryption Key: Independent 256-bit key for AES-256-GCM application field-level encryption.
 * Both keys are separately wrapped with unique salts and nonces using PBKDF2WithHmacSHA256 and AES-GCM.
 */
public final class VaultKeyManager {
    public static final int SALT_LENGTH_BYTES = 16;
    public static final int GCM_IV_LENGTH_BYTES = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int KEY_LENGTH_BYTES = 32;
    public static final int PBKDF2_ITERATIONS = 100_000;

    private static final String META_FILENAME = "vault-key.meta";

    private final Path keyMetaPath;
    private final SecureRandom secureRandom;

    public static final class VaultKeys {
        private final byte[] databaseKey;
        private final byte[] recordKey;

        public VaultKeys(byte[] databaseKey, byte[] recordKey) {
            this.databaseKey = databaseKey;
            this.recordKey = recordKey;
        }

        public byte[] getDatabaseKey() {
            return databaseKey;
        }

        public byte[] getRecordKey() {
            return recordKey;
        }

        public void clear() {
            VaultKeyManager.clear(databaseKey);
            VaultKeyManager.clear(recordKey);
        }
    }

    public VaultKeyManager() {
        this(AppConfig.databaseFile().toAbsolutePath().getParent().resolve(META_FILENAME));
    }

    public VaultKeyManager(Path keyMetaPath) {
        this.keyMetaPath = keyMetaPath;
        this.secureRandom = new SecureRandom();
    }

    public boolean isInitialized() {
        return Files.exists(keyMetaPath) && Files.isRegularFile(keyMetaPath);
    }

    public Path getKeyMetaPath() {
        return keyMetaPath;
    }

    /**
     * Initializes a new vault master key, generating independent 256-bit database and record keys.
     */
    public VaultKeys setupKeys(char[] masterPassword) throws GeneralSecurityException, IOException {
        if (masterPassword == null || masterPassword.length < 8) {
            throw new IllegalArgumentException("Master password must be at least 8 characters.");
        }
        if (isInitialized()) {
            throw new IllegalStateException("Vault is already initialized.");
        }

        byte[] dbKey = new byte[KEY_LENGTH_BYTES];
        secureRandom.nextBytes(dbKey);
        byte[] dbSalt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(dbSalt);
        byte[] dbIv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(dbIv);
        byte[] wrappedDbKey = wrapKey(masterPassword, dbSalt, dbIv, PBKDF2_ITERATIONS, dbKey);

        byte[] recordKey = new byte[KEY_LENGTH_BYTES];
        secureRandom.nextBytes(recordKey);
        byte[] recordSalt = new byte[SALT_LENGTH_BYTES];
        secureRandom.nextBytes(recordSalt);
        byte[] recordIv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(recordIv);
        byte[] wrappedRecordKey = wrapKey(masterPassword, recordSalt, recordIv, PBKDF2_ITERATIONS, recordKey);

        saveDualMetadata(dbSalt, dbIv, wrappedDbKey, recordSalt, recordIv, wrappedRecordKey, PBKDF2_ITERATIONS);

        return new VaultKeys(dbKey, recordKey);
    }

    public byte[] setupMasterKey(char[] masterPassword) throws GeneralSecurityException, IOException {
        VaultKeys keys = setupKeys(masterPassword);
        clear(keys.getRecordKey());
        return keys.getDatabaseKey();
    }

    /**
     * Unwraps both the database key and record key using the provided master password.
     */
    public VaultKeys unlockKeys(char[] masterPassword) throws GeneralSecurityException, IOException {
        if (!isInitialized()) {
            throw new IllegalStateException("Vault is not initialized. Please set up a master password first.");
        }
        if (masterPassword == null) {
            throw new IllegalArgumentException("Master password cannot be null.");
        }

        Properties props = loadMetadata();
        int iterations = Integer.parseInt(props.getProperty("iterations", String.valueOf(PBKDF2_ITERATIONS)));

        // Unwrap Database Key
        byte[] dbSalt = HexFormat.of().parseHex(props.getProperty("db.salt", props.getProperty("salt")));
        byte[] dbIv = HexFormat.of().parseHex(props.getProperty("db.iv", props.getProperty("iv")));
        byte[] wrappedDbKey = HexFormat.of().parseHex(props.getProperty("db.wrappedKey", props.getProperty("wrappedKey")));
        byte[] dbKey = unwrapKey(masterPassword, dbSalt, dbIv, iterations, wrappedDbKey);

        // Unwrap Record Key
        byte[] recordKey;
        if (props.containsKey("record.wrappedKey")) {
            byte[] recordSalt = HexFormat.of().parseHex(props.getProperty("record.salt"));
            byte[] recordIv = HexFormat.of().parseHex(props.getProperty("record.iv"));
            byte[] wrappedRecordKey = HexFormat.of().parseHex(props.getProperty("record.wrappedKey"));
            recordKey = unwrapKey(masterPassword, recordSalt, recordIv, iterations, wrappedRecordKey);
        } else {
            // Upgrade legacy v1 metadata: generate and persist fresh record key
            recordKey = new byte[KEY_LENGTH_BYTES];
            secureRandom.nextBytes(recordKey);
            byte[] recordSalt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(recordSalt);
            byte[] recordIv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(recordIv);
            byte[] wrappedRecordKey = wrapKey(masterPassword, recordSalt, recordIv, iterations, recordKey);
            saveDualMetadata(dbSalt, dbIv, wrappedDbKey, recordSalt, recordIv, wrappedRecordKey, iterations);
        }

        return new VaultKeys(dbKey, recordKey);
    }

    public byte[] unlock(char[] masterPassword) throws GeneralSecurityException, IOException {
        VaultKeys keys = unlockKeys(masterPassword);
        clear(keys.getRecordKey());
        return keys.getDatabaseKey();
    }

    public void changeMasterPassword(char[] oldPassword, char[] newPassword) throws GeneralSecurityException, IOException {
        if (newPassword == null || newPassword.length < 8) {
            throw new IllegalArgumentException("New master password must be at least 8 characters.");
        }
        VaultKeys keys = unlockKeys(oldPassword);
        try {
            byte[] dbSalt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(dbSalt);
            byte[] dbIv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(dbIv);
            byte[] wrappedDbKey = wrapKey(newPassword, dbSalt, dbIv, PBKDF2_ITERATIONS, keys.getDatabaseKey());

            byte[] recordSalt = new byte[SALT_LENGTH_BYTES];
            secureRandom.nextBytes(recordSalt);
            byte[] recordIv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(recordIv);
            byte[] wrappedRecordKey = wrapKey(newPassword, recordSalt, recordIv, PBKDF2_ITERATIONS, keys.getRecordKey());

            saveDualMetadata(dbSalt, dbIv, wrappedDbKey, recordSalt, recordIv, wrappedRecordKey, PBKDF2_ITERATIONS);
        } finally {
            keys.clear();
        }
    }

    private byte[] wrapKey(char[] password, byte[] salt, byte[] iv, int iterations, byte[] rawKey)
            throws GeneralSecurityException {
        SecretKey masterKey = deriveKey(password, salt, iterations);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec);
        return cipher.doFinal(rawKey);
    }

    private byte[] unwrapKey(char[] password, byte[] salt, byte[] iv, int iterations, byte[] wrappedKey)
            throws GeneralSecurityException {
        SecretKey masterKey = deriveKey(password, salt, iterations);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, masterKey, spec);
        return cipher.doFinal(wrappedKey);
    }

    private SecretKey deriveKey(char[] password, byte[] salt, int iterations) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        spec.clearPassword();
        return new SecretKeySpec(keyBytes, "AES");
    }

    private void saveDualMetadata(byte[] dbSalt, byte[] dbIv, byte[] wrappedDbKey,
                                  byte[] recordSalt, byte[] recordIv, byte[] wrappedRecordKey,
                                  int iterations) throws IOException {
        Files.createDirectories(keyMetaPath.toAbsolutePath().getParent());
        Properties props = new Properties();
        props.setProperty("version", "2");
        props.setProperty("kdf", "PBKDF2WithHmacSHA256");
        props.setProperty("cipher", "AES/GCM/NoPadding");
        props.setProperty("iterations", String.valueOf(iterations));

        // Database encryption metadata (with backward compatible fallback names)
        props.setProperty("salt", HexFormat.of().formatHex(dbSalt));
        props.setProperty("iv", HexFormat.of().formatHex(dbIv));
        props.setProperty("wrappedKey", HexFormat.of().formatHex(wrappedDbKey));
        props.setProperty("db.salt", HexFormat.of().formatHex(dbSalt));
        props.setProperty("db.iv", HexFormat.of().formatHex(dbIv));
        props.setProperty("db.wrappedKey", HexFormat.of().formatHex(wrappedDbKey));

        // Record encryption metadata
        props.setProperty("record.salt", HexFormat.of().formatHex(recordSalt));
        props.setProperty("record.iv", HexFormat.of().formatHex(recordIv));
        props.setProperty("record.wrappedKey", HexFormat.of().formatHex(wrappedRecordKey));

        Path tempFile = Files.createTempFile(keyMetaPath.getParent(), "vault-meta", ".tmp");
        try (var out = Files.newOutputStream(tempFile)) {
            props.store(out, "VaultLedger Dual Key Metadata - Contains NO plaintext secrets");
        }
        Files.move(tempFile, keyMetaPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    private Properties loadMetadata() throws IOException {
        Properties props = new Properties();
        try (var in = Files.newInputStream(keyMetaPath)) {
            props.load(in);
        }
        return props;
    }

    public static void clear(byte[] array) {
        if (array != null) {
            Arrays.fill(array, (byte) 0);
        }
    }

    public static void clear(char[] array) {
        if (array != null) {
            Arrays.fill(array, '\0');
        }
    }
}
