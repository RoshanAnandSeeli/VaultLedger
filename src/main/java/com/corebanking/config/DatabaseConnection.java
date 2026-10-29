package com.corebanking.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public final class DatabaseConnection {
    private static volatile String activeEncryptionKeyHex = null;

    private DatabaseConnection() {
    }

    public static void setActiveEncryptionKeyHex(String hexKey) {
        activeEncryptionKeyHex = hexKey;
    }

    public static String getActiveEncryptionKeyHex() {
        return activeEncryptionKeyHex;
    }

    public static void clearActiveEncryptionKey() {
        activeEncryptionKeyHex = null;
    }

    public static Connection openConnection(Path databaseFile) throws SQLException {
        return openConnection(databaseFile, activeEncryptionKeyHex);
    }

    public static Connection openConnection(Path databaseFile, String encryptionKeyHex) throws SQLException {
        try {
            Files.createDirectories(databaseFile.toAbsolutePath().getParent());
        } catch (IOException exception) {
            throw new SQLException("Unable to create the database directory.", exception);
        }

        String jdbcUrl;
        if (encryptionKeyHex != null && !encryptionKeyHex.isBlank()) {
            jdbcUrl = "jdbc:sqlite:file:" + databaseFile.toAbsolutePath().toUri().getPath()
                    + "?cipher=sqlcipher&key=x'" + encryptionKeyHex + "'&legacy=4";
        } else {
            jdbcUrl = "jdbc:sqlite:" + databaseFile.toAbsolutePath();
        }

        Connection connection = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        return connection;
    }
}
