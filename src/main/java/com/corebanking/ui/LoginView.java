package com.corebanking.ui;

import com.corebanking.config.AppConfig;
import com.corebanking.security.DatabaseMigrator;
import com.corebanking.security.VaultKeyManager;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

import java.nio.file.Path;
import java.util.HexFormat;
import java.util.function.Consumer;

/**
 * JavaFX presentation view for Master Password setup and Vault database unlocking.
 * Ensures the encrypted database is never opened prior to successful authentication.
 */
public final class LoginView {
    private final VaultKeyManager keyManager;
    private final Consumer<VaultKeyManager.VaultKeys> onUnlocked;
    private final StackPane root = new StackPane();

    public LoginView(VaultKeyManager keyManager, Consumer<VaultKeyManager.VaultKeys> onUnlocked) {
        this.keyManager = keyManager;
        this.onUnlocked = onUnlocked;
    }

    public Parent build() {
        root.getStyleClass().add("app-root");
        root.setAlignment(Pos.CENTER);
        root.setPadding(new Insets(32));

        VBox card = new VBox(20);
        card.getStyleClass().add("dialog-panel");
        card.setMaxWidth(460);
        card.setAlignment(Pos.TOP_LEFT);

        // Brand section
        Label badge = new Label("ENCRYPTED AT REST • AES-256 SQLCIPHER");
        badge.setStyle("-fx-font-size: 11px; -fx-font-weight: bold; -fx-text-fill: #009C9C; -fx-letter-spacing: 1px;");

        Label brand = new Label("VAULTLEDGER");
        brand.getStyleClass().add("brand");
        brand.setStyle("-fx-font-size: 24px; -fx-font-weight: 800;");

        Label subtitle = new Label("Core Banking Account Lifecycle & Ledger System");
        subtitle.getStyleClass().add("brand-subtitle");
        subtitle.setStyle("-fx-font-size: 13px; -fx-text-fill: #7A92A5;");

        VBox brandBox = new VBox(6, badge, brand, subtitle);

        boolean isSetup = !keyManager.isInitialized();

        Label formTitle = new Label(isSetup ? "Initialize Master Security Key" : "Unlock Banking Vault");
        formTitle.setStyle("-fx-font-size: 18px; -fx-font-weight: 700; -fx-text-fill: #142B3A;");

        Label instructions = new Label(isSetup
                ? "Create a master password (minimum 8 characters) to encrypt the core banking database. Your password securely wraps a cryptographically generated 256-bit database key."
                : "Enter your master password to unlock and decrypt the core banking ledger database.");
        instructions.setWrapText(true);
        instructions.setStyle("-fx-font-size: 13px; -fx-text-fill: #556B7D; -fx-line-spacing: 2px;");

        // Form fields
        Label passLabel = new Label("Master Password");
        passLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 600; -fx-text-fill: #2C3E50;");
        PasswordField passField = new PasswordField();
        passField.setPromptText("Enter master password");
        passField.setStyle("-fx-font-size: 14px; -fx-padding: 10px;");

        PasswordField confirmPassField = new PasswordField();
        confirmPassField.setPromptText("Confirm master password");
        confirmPassField.setStyle("-fx-font-size: 14px; -fx-padding: 10px;");
        Label confirmLabel = new Label("Confirm Master Password");
        confirmLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 600; -fx-text-fill: #2C3E50;");

        Label errorLabel = new Label();
        errorLabel.setWrapText(true);
        errorLabel.setStyle("-fx-font-size: 12px; -fx-font-weight: 600; -fx-text-fill: #C53030;");
        errorLabel.setVisible(false);
        errorLabel.setManaged(false);

        Button submitBtn = new Button(isSetup ? "Initialize & Encrypt Vault" : "Unlock Database");
        submitBtn.getStyleClass().add("primary-button");
        submitBtn.setMaxWidth(Double.MAX_VALUE);
        submitBtn.setStyle("-fx-font-size: 14px; -fx-font-weight: bold; -fx-padding: 11px;");

        Runnable handleSubmit = () -> {
            String password = passField.getText();
            if (password == null || password.length() < 8) {
                showError(errorLabel, "Password must be at least 8 characters long.");
                return;
            }

            if (isSetup) {
                String confirm = confirmPassField.getText();
                if (!password.equals(confirm)) {
                    showError(errorLabel, "Passwords do not match. Please verify and try again.");
                    return;
                }
            }

            errorLabel.setVisible(false);
            errorLabel.setManaged(false);
            submitBtn.setDisable(true);
            submitBtn.setText(isSetup ? "Initializing Encryption..." : "Decrypting Vault...");

            // Process cryptographic key unwrapping on background thread
            new Thread(() -> {
                char[] passChars = password.toCharArray();
                try {
                    VaultKeyManager.VaultKeys keys;
                    if (isSetup) {
                        keys = keyManager.setupKeys(passChars);
                        String hexKey = HexFormat.of().formatHex(keys.getDatabaseKey());

                        // If unencrypted database exists, migrate safely with backup
                        Path dbPath = AppConfig.databaseFile();
                        if (DatabaseMigrator.isPlaintextDatabase(dbPath)) {
                            DatabaseMigrator.migrateToEncrypted(dbPath, hexKey);
                        }

                        Platform.runLater(() -> onUnlocked.accept(keys));
                    } else {
                        keys = keyManager.unlockKeys(passChars);
                        Platform.runLater(() -> onUnlocked.accept(keys));
                    }
                } catch (Exception ex) {
                    Platform.runLater(() -> {
                        submitBtn.setDisable(false);
                        submitBtn.setText(isSetup ? "Initialize & Encrypt Vault" : "Unlock Database");
                        showError(errorLabel, "Authentication failed. Invalid master password or corrupted database.");
                        passField.clear();
                        if (isSetup) {
                            confirmPassField.clear();
                        }
                    });
                } finally {
                    VaultKeyManager.clear(passChars);
                }
            }).start();
        };

        submitBtn.setOnAction(e -> handleSubmit.run());
        passField.setOnAction(e -> handleSubmit.run());
        confirmPassField.setOnAction(e -> handleSubmit.run());

        VBox form = new VBox(12);
        if (isSetup) {
            form.getChildren().addAll(passLabel, passField, confirmLabel, confirmPassField);
        } else {
            form.getChildren().addAll(passLabel, passField);
        }

        card.getChildren().addAll(brandBox, formTitle, instructions, form, errorLabel, submitBtn);
        root.getChildren().add(card);
        return root;
    }

    private void showError(Label label, String message) {
        label.setText(message);
        label.setVisible(true);
        label.setManaged(true);
    }
}

