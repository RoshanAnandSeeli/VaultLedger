package com.corebanking;

import com.corebanking.config.AppConfig;
import com.corebanking.config.DatabaseConnection;
import com.corebanking.config.DatabaseInitializer;
import com.corebanking.repository.AccountRepository;
import com.corebanking.repository.BankRepository;
import com.corebanking.security.DatabaseMigrator;
import com.corebanking.security.RecordEncryptionService;
import com.corebanking.security.VaultKeyManager;
import com.corebanking.service.AccountService;
import com.corebanking.service.AccountServiceImpl;
import com.corebanking.service.BankService;
import com.corebanking.service.BankServiceImpl;
import com.corebanking.service.DatabaseManagementService;
import com.corebanking.service.DatabaseManagementServiceImpl;
import com.corebanking.service.TransactionService;
import com.corebanking.service.TransactionServiceImpl;
import com.corebanking.ui.AppShell;
import com.corebanking.ui.LoginView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.sql.Connection;

public final class Main extends Application {
    private Connection connection;
    private Stage stage;

    @Override
    public void start(Stage stage) {
        this.stage = stage;
        stage.setMinWidth(900);
        stage.setMinHeight(600);
        stage.setOnCloseRequest(event -> closeConnection());
        showLoginScreen();
    }

    private void showLoginScreen() {
        VaultKeyManager keyManager = new VaultKeyManager();
        LoginView loginView = new LoginView(keyManager, this::onUnlocked);

        Scene scene = new Scene(loginView.build(), 980, 680);
        var css = getClass().getResource("/css/application.css");
        if (css != null) {
            scene.getStylesheets().add(css.toExternalForm());
        }

        stage.setTitle("VaultLedger — Unlock Secure Vault");
        stage.setScene(scene);
        stage.show();
    }

    private void onUnlocked(VaultKeyManager.VaultKeys keys) {
        try {
            String hexKey = java.util.HexFormat.of().formatHex(keys.getDatabaseKey());
            DatabaseConnection.setActiveEncryptionKeyHex(hexKey);
            RecordEncryptionService.setActive(new RecordEncryptionService(keys.getRecordKey()));
            keys.clear();

            connection = DatabaseConnection.openConnection(AppConfig.databaseFile());
            DatabaseInitializer.initialize(connection);
            DatabaseMigrator.migrateRecordEncryption(AppConfig.databaseFile(), connection, RecordEncryptionService.getActive());
            DatabaseMigrator.cleanupLegacyPlaintextBackups(AppConfig.databaseFile().getParent());

            AccountRepository accountRepository = new AccountRepository(connection);
            AccountService accountService = new AccountServiceImpl(accountRepository, new BankRepository(connection));
            BankService bankService = new BankServiceImpl(new BankRepository(connection));
            TransactionService transactionService = new TransactionServiceImpl(connection, accountService);
            DatabaseManagementService dbmService = new DatabaseManagementServiceImpl(connection);

            AppShell shell = new AppShell(connection, accountService, bankService, transactionService, dbmService);
            shell.setOnLogout(() -> {
                closeConnection();
                showLoginScreen();
            });

            Scene scene = new Scene(shell.build(), 1340, 840);
            var css = getClass().getResource("/css/application.css");
            if (css != null) {
                scene.getStylesheets().add(css.toExternalForm());
            }

            stage.setTitle("VaultLedger — Core Banking Account Lifecycle & Ledger System");
            stage.setScene(scene);
            stage.setMinWidth(1100);
            stage.setMinHeight(720);
        } catch (Exception exception) {
            closeConnection();
            System.err.println("Database initialization failed: " + exception.getMessage());
            showLoginScreen();
        }
    }

    @Override
    public void stop() {
        closeConnection();
    }

    private void closeConnection() {
        if (connection != null) {
            try {
                connection.close();
            } catch (Exception ignored) {
                // The connection is already closing
            }
            connection = null;
        }
        DatabaseConnection.clearActiveEncryptionKey();
        RecordEncryptionService.clearActive();
    }

    public static void main(String[] args) {
        // Database is not opened or initialized here.
        // Initialization strictly occurs only after successful master password unlock.
        launch(args);
    }
}
