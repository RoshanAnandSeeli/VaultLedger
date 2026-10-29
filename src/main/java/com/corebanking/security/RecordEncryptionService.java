package com.corebanking.security;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Application-level record and field encryption service using AES-256-GCM.
 * Every encryption operation utilizes a fresh, cryptographically secure 12-byte nonce.
 * Ciphertexts are stored in a versioned format: "enc:v1:<Base64([12-byte nonce][ciphertext + tag])>".
 * Decryption validates authentication tags to safely reject tampered data.
 */
public final class RecordEncryptionService {
    public static final String PREFIX = "enc:v1:";
    public static final int GCM_IV_LENGTH_BYTES = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int KEY_LENGTH_BYTES = 32;

    private static volatile RecordEncryptionService activeInstance = null;

    private final SecretKey key;
    private final byte[] keyBytes;
    private final SecureRandom secureRandom;
    private volatile boolean destroyed;

    public RecordEncryptionService(byte[] keyBytes) {
        if (keyBytes == null || keyBytes.length != KEY_LENGTH_BYTES) {
            throw new IllegalArgumentException("Record encryption key must be 32 bytes (256 bits).");
        }
        this.keyBytes = Arrays.copyOf(keyBytes, keyBytes.length);
        this.key = new SecretKeySpec(this.keyBytes, "AES");
        this.secureRandom = new SecureRandom();
    }

    public static void setActive(RecordEncryptionService service) {
        activeInstance = service;
    }

    public static RecordEncryptionService getActive() {
        return activeInstance;
    }

    public static void clearActive() {
        if (activeInstance != null) {
            activeInstance.destroy();
            activeInstance = null;
        }
    }

    /**
     * Encrypts plaintext string using AES-256-GCM.
     * Idempotent: If value is null or already starts with "enc:v1:", returns it unmodified.
     */
    public String encrypt(String plaintext) {
        if (plaintext == null) {
            return null;
        }
        if (plaintext.startsWith(PREFIX)) {
            return plaintext; // Avoid double-encryption
        }
        checkNotDestroyed();

        try {
            byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertextWithTag = cipher.doFinal(plaintextBytes);

            byte[] combined = new byte[iv.length + ciphertextWithTag.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertextWithTag, 0, combined, iv.length, ciphertextWithTag.length);

            return PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Record encryption failed.", e);
        }
    }

    /**
     * Decrypts an authenticated ciphertext string.
     * If value is null, returns null.
     * If value does not start with "enc:v1:", assumes legacy plaintext and returns it safely.
     * Fails with GeneralSecurityException if ciphertext, nonce, or tag was tampered with.
     */
    public String decrypt(String ciphertext) throws GeneralSecurityException {
        if (ciphertext == null) {
            return null;
        }
        if (!ciphertext.startsWith(PREFIX)) {
            return ciphertext; // Plaintext pass-through
        }
        checkNotDestroyed();

        String b64Payload = ciphertext.substring(PREFIX.length());
        byte[] combined;
        try {
            combined = Base64.getDecoder().decode(b64Payload);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid base64 encoding in ciphertext payload.", e);
        }

        if (combined.length < GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8)) {
            throw new GeneralSecurityException("Truncated ciphertext payload.");
        }

        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH_BYTES);

        int cipherLength = combined.length - GCM_IV_LENGTH_BYTES;
        byte[] cipherWithTag = new byte[cipherLength];
        System.arraycopy(combined, GCM_IV_LENGTH_BYTES, cipherWithTag, 0, cipherLength);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        byte[] decryptedBytes = cipher.doFinal(cipherWithTag);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public boolean isDestroyed() {
        return destroyed;
    }

    public synchronized void destroy() {
        if (!destroyed) {
            Arrays.fill(keyBytes, (byte) 0);
            destroyed = true;
        }
    }

    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("RecordEncryptionService has been destroyed/cleared.");
        }
    }
}

