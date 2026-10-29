# VaultLedger — Core Banking Account Lifecycle & Ledger System

[![Java Version](https://img.shields.io/badge/Java-17%2B-blue.svg)](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
[![JavaFX](https://img.shields.io/badge/JavaFX-21.0.5-orange.svg)](https://openjfx.io/)
[![Database Encryption](https://img.shields.io/badge/Database%20Encryption-SQLCipher%20256--bit-brightgreen.svg)](https://github.com/willena/sqlite-jdbc-crypt)
[![Record Encryption](https://img.shields.io/badge/Record%20Encryption-AES--256--GCM-teal.svg)](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
[![Build Tool](https://img.shields.io/badge/Maven-3.x-red.svg)](https://maven.apache.org/)
[![Tests](https://img.shields.io/badge/Tests-119%20Passed-brightgreen.svg)]()
[![Repository](https://img.shields.io/badge/GitHub-RoshanAnandSeeli%2FVaultLedger-blue.svg)](https://github.com/RoshanAnandSeeli/VaultLedger)

> **Academic Notice:** **VaultLedger** is an academic desktop banking simulation engineered to demonstrate core banking principles, double-entry bookkeeping, strict account lifecycle states, atomic transactions, thread-safe concurrency controls, and defense-in-depth dual-layer cryptographic security. It is designed strictly for educational and evaluation purposes and is not intended for production banking deployments or real customer funds.

**Official Repository:** [https://github.com/RoshanAnandSeeli/VaultLedger](https://github.com/RoshanAnandSeeli/VaultLedger)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Key Differentiators & Security Architecture](#2-key-differentiators--security-architecture)
3. [Features](#3-features)
4. [Technology Stack](#4-technology-stack)
5. [Project Architecture](#5-project-architecture)
6. [Prerequisites](#6-prerequisites)
7. [Clone and Run on Windows](#7-clone-and-run-on-windows)
8. [Clone and Run on macOS / Linux](#8-clone-and-run-on-macos--linux)
9. [First Launch, Master Key Setup & Demo Data](#9-first-launch-master-key-setup--demo-data)
10. [Complete UI User Guide](#10-complete-ui-user-guide)
11. [Demonstration Scenarios](#11-demonstration-scenarios)
12. [Testing & Verification](#12-testing--verification)
13. [Troubleshooting](#13-troubleshooting)
14. [GitHub Repository & Contribution Workflow](#14-github-repository--contribution-workflow)
15. [Academic Disclaimer](#15-academic-disclaimer)

---

## 1. Project Overview

**VaultLedger** is an enterprise-grade core banking desktop simulation application developed in **Java 17**, **JavaFX 21**, and **SQLite 3 with SQLCipher encryption**. It models how modern financial institutions manage account lifecycles, enforce relational integrity, execute atomic ACID transactions, maintain an immutable balanced double-entry accounting ledger, and secure sensitive financial records at rest using a multi-tier defense-in-depth cryptographic model.

The application allows students, evaluators, and developers to observe how transactions move through the system:
- From the **JavaFX presentation tier**,
- Through the **Master Password Authentication & Unlock barrier**,
- Across the **Service validation tier**,
- Coordinated by the **AccountLockManager thread-safe concurrency engine**,
- Encrypted by the **Application-level Record Encryption Service (AES-256-GCM)**,
- Persisted through the **JDBC DAO tier into an AES-256 SQLCipher encrypted database**,
- And finally audited on an immutable **double-entry general ledger**.

---

## 2. Key Differentiators & Security Architecture

Unlike conventional banking CRUD coursework, VaultLedger incorporates professional banking and security patterns:

### 1. Dual-Layer Defense-in-Depth Cryptography
* **Layer 1 — Whole-Database Encryption at Rest:**
  * Uses `io.github.willena:sqlite-jdbc:3.50.1.0` (SQLite3MultipleCiphers / SQLCipher compatible).
  * Every page of the SQLite database file (`data/core-banking.db`) is encrypted on disk using a 256-bit key ($K_{db}$).
  * Standard SQLite viewers and tools cannot read, parse, or identify the file without authentication.
* **Layer 2 — Application-Level Record Encryption (`AES-256-GCM`):**
  * Implemented via [`RecordEncryptionService`](src/main/java/com/corebanking/security/RecordEncryptionService.java).
  * Sensitive customer fields (`customer_name`, `age`, `email`, `phone_number`) and transaction descriptions are encrypted in memory before reaching SQLite.
  * Uses a fresh, cryptographically secure 12-byte random nonce per operation, producing ciphertext format `enc:v1:<Base64([12-byte IV][Ciphertext + 16-byte Tag])>`.
  * Authenticated decryption rejects bit-flipping, truncation, or payload tampering safely with exceptions.
  * Transparent in-memory search enables searching decrypted records in Java without leaking frequency patterns via SQL LIKE queries.

### 2. Zero-Knowledge Dual-Key Lifecycle Management
* Implemented in [`VaultKeyManager`](src/main/java/com/corebanking/security/VaultKeyManager.java).
* Derives two independent 256-bit keys ($K_{db}$ and $K_{record}$) using `SecureRandom`.
* Both keys are independently wrapped using the user's master password via **PBKDF2-HMAC-SHA-256 (100,000 iterations)** with distinct random 16-byte salts and distinct 12-byte GCM nonces.
* Stored in `vault-key.meta` version 2 metadata. Contains **no plaintext passwords and no unwrapped keys**.
* Unwrapped keys and password character arrays are zeroized from memory immediately after authentication or upon logout.

### 3. Deadlock-Aware Account Locking
* Implemented in [`AccountLockManager`](src/main/java/com/corebanking/transaction/AccountLockManager.java).
* Inter-account transfers acquire `ReentrantLock` instances using strict lexicographical ID ordering.
* Completely eliminates race conditions and circular lock wait conditions regardless of transfer concurrency or direction.

### 4. Atomic Database Transactions with Double-Entry Ledger Validation
* Balances, transaction logs, and dual debit/credit ledger records execute inside atomic JDBC transactions.
* If a balance update fails, an overdraft occurs, or ledger entries do not balance, the entire database transaction rolls back, leaving no orphan records.

### 5. Automated Protected Backups
* Implemented in [`DatabaseMigrator`](src/main/java/com/corebanking/security/DatabaseMigrator.java).
* Retained database backups (`*.backup.*`) are verified encrypted copies at rest.
* Ephemeral plaintext migration safety files are purged immediately upon migration success, leaving zero plaintext data on disk.
* Intelligent pre-flight checks prevent redundant backup creation on subsequent application launches when no migration is required.

---

## 3. Features

* **Master Password Unlock & Setup:** Dedicated presentation screen enforcing credential verification before opening the database connection.
* **Executive Dashboard & Real-Time Metrics:** Live metric cards summarizing Total Accounts, Active Accounts, Visible Banks, Aggregate Customer Balance, and recent financial activity.
* **Customer Onboarding & Account Registration:** Validated form enforcing account ID generation, name, age restrictions (18–120), valid email format, 10–15 digit phone format, bank affiliation, and account type (`SAVINGS` or `CURRENT`).
* **Strict Three-State Account Lifecycle:**
  - **`ACTIVE`:** Eligible for deposits, withdrawals, and transfers.
  - **`INACTIVE`:** Dormant state; financial transactions are blocked; can be reactivated.
  - **`CLOSED`:** Terminal state; requires zero balance; cannot be reopened; eligible for permanent deletion.
* **Atomic Cash Operations:** Deposits backed by the system cash pool (`SYSTEM-CASH`) and withdrawals with overdraft prevention.
* **Inter-Account Transfers:** Coordinated dual-account movements with live calculation previews and deadlock prevention.
* **Audit Transaction Receipts:** Immediate modal receipt for every completed transaction displaying Transaction ID, Timestamp, Type, Accounts, Amount, Status, and Description.
* **Double-Entry General Ledger:** Relational ledger capturing matched `DEBIT` and `CREDIT` entries with mathematical balance verification displayed via a `BALANCED` badge.
* **Searchable Historical Activity:** Search and dropdown filtering across accounts, transactions, and ledger history.
* **Granular Database Maintenance:** Ability to reset demo data or wipe the workspace with confirmation guards.
* **Session Logout / Vault Lock:** Closes active database connections and wipes active encryption keys from memory, returning to the lock screen.

---

## 4. Technology Stack

| Layer | Component | Version / Specification | Details |
| :--- | :--- | :--- | :--- |
| **Language** | Java (JDK) | 17 LTS / 21+ / 24 | Modern Java syntax (records, pattern matching, sealed types) |
| **GUI Framework** | OpenJFX (JavaFX) | 21.0.5 | Native desktop UI, Controls, Layouts, CSS styling |
| **Encrypted Database** | SQLite (SQLCipher) | 3.50.1.0 | `io.github.willena:sqlite-jdbc` with SQLite3MultipleCiphers AES-256 |
| **Record Encryption** | Java JCA | AES-256-GCM | 256-bit AES key, 12-byte random nonce per op, authenticated tag |
| **Key Derivation** | PBKDF2 | HMAC-SHA-256 | 100,000 iterations with distinct 16-byte random salts |
| **Build System** | Apache Maven | 3.8+ / 3.9.9 | Dependency management, build lifecycle, JavaFX Maven plugin |
| **Testing** | JUnit Jupiter | 5.11.0 | Unit, integration, concurrency, and security test suite (**119 tests**) |
| **Concurrency** | Java Concurrency | `java.util.concurrent` | `ReentrantLock` striping and lexicographical ordering |
| **Styling** | JavaFX CSS | Custom 3.0 Design | VaultLedger Navy (`#0A1728`), Teal (`#009C9C`), and Clean Light (`#FFFFFF`) |

---

## 5. Project Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    JavaFX Presentation Tier                 │
│         LoginView, AppShell, DialogWindow, AlertUtil        │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Security & Lifecycle Tier                │
│    VaultKeyManager (PBKDF2/GCM), RecordEncryptionService,   │
│                 DatabaseMigrator (Encrypted Backup)         │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                      Service Logic Tier                     │
│    AccountService, TransactionService, LedgerService,       │
│    BankService, DatabaseManagementService                   │
│    ┌───────────────────────────────────────────────────┐    │
│    │    AccountLockManager (Deadlock-Free Locking)     │    │
│    └───────────────────────────────────────────────────┘    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Repository Access Tier                   │
│    AccountRepository, TransactionRepository,               │
│    LedgerRepository, BankRepository                         │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                Whole-Database Encrypted Storage             │
│            SQLite3MultipleCiphers (data/core-banking.db)    │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```text
VaultLedger/
├── data/                                 # Runtime encrypted database directory (git-ignored)
│   ├── core-banking.db                   # SQLCipher AES-256 encrypted database file
│   └── vault-key.meta                    # Cryptographic envelope metadata (no plaintext secrets)
├── src/
│   ├── main/
│   │   ├── java/com/corebanking/
│   │   │   ├── config/                   # DB connection, transactions, seeder, initializer
│   │   │   │   ├── AppConfig.java
│   │   │   │   ├── DatabaseConfig.java
│   │   │   │   ├── DatabaseConnection.java
│   │   │   │   ├── DatabaseInitializer.java
│   │   │   │   ├── DatabaseTransaction.java
│   │   │   │   └── DemoDataSeeder.java
│   │   │   ├── enums/                    # AccountType, AccountStatus, TransactionType, LedgerEntryType
│   │   │   ├── exception/                # Domain banking exceptions (InsufficientFunds, etc.)
│   │   │   ├── model/                    # Immutable domain models (Account, Bank, Transaction, LedgerEntry)
│   │   │   ├── repository/               # JDBC DAOs with transparent field encryption/decryption
│   │   │   ├── security/                 # Dual-layer encryption engine
│   │   │   │   ├── DatabaseMigrator.java         # Safe encrypted migration & backup
│   │   │   │   ├── RecordEncryptionService.java  # AES-256-GCM record cipher
│   │   │   │   └── VaultKeyManager.java          # Dual-key derivation & unwrapping
│   │   │   ├── service/                  # Business services and interfaces
│   │   │   ├── transaction/              # AccountLockManager for lock ordering
│   │   │   ├── ui/                       # Presentation tier (LoginView, AppShell)
│   │   │   │   └── util/                 # AlertUtil, FormatUtil
│   │   │   └── Main.java                 # Desktop application entry point
│   │   └── resources/
│   │       ├── css/application.css       # VaultLedger professional banking styling
│   │       └── database/schema.sql       # Relational database schema & indexes
│   └── test/java/com/corebanking/        # 119 automated unit, integration, & security tests
│       ├── security/
│       │   ├── DatabaseEncryptionTest.java # 14 database encryption tests
│       │   └── RecordEncryptionTest.java   # 11 record encryption tests
│       └── ...                           # Domain, Service, Concurrency, and UI tests
├── pom.xml                               # Maven project definition
├── run.bat                               # Windows launcher with Java & Maven auto-detection
├── userinst.md                           # Extended user manual and demonstration script
└── README.md                             # Project documentation (this file)
```

---

## 6. Prerequisites

Ensure your system has:
1. **Java Development Kit (JDK) 17 or higher** installed.
2. **Apache Maven 3.8+** installed.
3. **Git** installed.

---

## 7. Clone and Run on Windows

### Step 1: Clone Repository
```powershell
git clone https://github.com/RoshanAnandSeeli/VaultLedger.git
cd VaultLedger
```

### Step 2: Launch Application
You can use the automated launcher script [`run.bat`](run.bat), which automatically detects installed JDKs (`jdk-24`, `jdk-21`, `jdk-17`) and Maven:

```cmd
run.bat
```

Or via Maven directly:
```powershell
mvn clean compile
mvn javafx:run
```

### Step 3: Run the Test Suite
```cmd
run.bat test
```
*(or `mvn test`)*

---

## 8. Clone and Run on macOS / Linux

### Step 1: Clone Repository
```bash
git clone https://github.com/RoshanAnandSeeli/VaultLedger.git
cd VaultLedger
```

### Step 2: Compile & Run
```bash
mvn clean compile
mvn javafx:run
```

### Step 3: Run Tests
```bash
mvn test
```

---

## 9. First Launch, Master Key Setup & Demo Data

### 1. Master Key Initialization
On first launch, VaultLedger presents the **Master Security Key Setup** screen:
1. Enter a secure master password (minimum 8 characters).
2. Confirm the master password.
3. Click **Initialize & Encrypt Vault**.
4. The system cryptographically derives independent 256-bit database and record keys, wraps them using PBKDF2-HMAC-SHA-256 (100,000 iterations), creates `data/vault-key.meta`, and provisions the encrypted database `data/core-banking.db`.

### 2. Unlocking on Subsequent Launches
On subsequent launches, enter your master password to unlock and decrypt the vault. If an incorrect password is entered, access is rejected without opening or altering the database.

### 3. Loading Demo Data
Once logged in, click **`Load Demo Data`** on the executive dashboard to populate sample accounts, a bank, and balanced transactions.

---

## 10. Complete UI User Guide

1. **Dashboard (`⊞ Dashboard`):** High-level operational summary cards and quick action buttons.
2. **Accounts Directory (`👥 Accounts`):** Filter and search customer accounts by name, account ID, email, or phone.
3. **Account Details:** Inspect balances, view transaction history, and perform operations:
   - **`+ Deposit`:** Credit funds.
   - **`- Withdraw`:** Debit funds with live overdraft protection.
   - **`⇄ Transfer`:** Move funds to another active account with dynamic destination filtering.
   - **`Activate` / `Deactivate`:** Change lifecycle status.
   - **`Close Account`:** Available only when balance is exactly ₹0.00.
4. **Transactions Log (`⇄ Transactions`):** Searchable log with type/status filters and receipt inspection.
5. **Double-Entry General Ledger (`📒 Ledger`):** Matched debits and credits with an automated mathematical balance verification banner.
6. **Lock Vault / Logout:** Located in the sidebar footer; securely closes connections, wipes keys from memory, and returns to the lock screen.

---

## 11. Demonstration Scenarios

* **Scenario 1:** Set up master password and observe key derivation in `vault-key.meta`.
* **Scenario 2:** Load demo data and inspect real-time metrics.
* **Scenario 3:** Onboard a new customer and verify age and contact validations.
* **Scenario 4:** Perform deposit and withdrawal; verify transaction receipt generation.
* **Scenario 5:** Transfer funds between accounts; verify simultaneous debit and credit updates.
* **Scenario 6:** Trigger insufficient funds overdraft protection.
* **Scenario 7:** Test account deactivation and transaction blocking.
* **Scenario 8:** Close a zero-balance account and verify lifecycle invariants.
* **Scenario 9:** Inspect the General Ledger and confirm debits equal credits (`BALANCED`).
* **Scenario 10:** Close the application, attempt to open `data/core-banking.db` in an ordinary SQLite viewer (confirming it is unreadable), and reopen in VaultLedger with your master password.

---

## 12. Testing & Verification

VaultLedger includes an automated test suite executed via JUnit 5:

```bash
mvn test
```

### Test Results
```text
[INFO] Results:
[INFO] Tests run: 119, Failures: 0, Errors: 0, Skipped: 0
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
```

### Test Coverage Highlights
* **Whole-Database Encryption (`DatabaseEncryptionTest`, 14 tests):** Password unlocking, invalid credential rejection, page-level confidentiality at rest, restart persistence, migration from plaintext, tamper rejection, rollback on failure, multi-threaded ledger balancing, logout cleanup, and encrypted backup verification.
* **Record-Level Field Encryption (`RecordEncryptionTest`, 11 tests):** Round-trip encryption/decryption, fresh nonce uniqueness, bit-flip tamper rejection, truncation handling, database column ciphertext inspection (`enc:v1:...`), in-memory search over decrypted data, and memory zeroization.
* **Concurrency & Deadlock Prevention (`ConcurrencyIntegrationTest`, 6 tests):** Concurrent deposits and bi-directional multi-threaded transfers proving thread safety without deadlocks.
* **Account Lifecycle & Management (`AccountServiceTest`, `AccountManagementTest`, 21 tests):** State transitions (`ACTIVE`, `INACTIVE`, `CLOSED`), age and contact validation, and account closures.
* **Double-Entry Ledger (`LedgerServiceTest`, 9 tests):** Dual debit/credit entry verification and mathematical invariant enforcement.
* **UI & Presentation (`AppShellUITest`, `TransactionDialogTest`, 3 tests):** Dialog components, calculation previews, and receipt generation.

---

## 13. Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **`java: command not found`** | JDK 17+ is not installed or not on PATH. | Install JDK 17 or run [`run.bat`](run.bat) on Windows (auto-detects Java). |
| **`mvn: command not found`** | Apache Maven is not in PATH. | Install Maven or use [`run.bat`](run.bat), which detects local Maven installations. |
| **Database cannot be opened in external viewer** | Database is encrypted at rest using SQLCipher. | This is by design. Open and unlock the database using the VaultLedger application. |
| **Authentication failed on unlock** | Incorrect master password entered. | Enter the password configured during vault setup. |
| **`Insufficient funds` error** | Withdrawal or transfer exceeds account balance. | Enter an amount less than or equal to the account balance. |
| **Account dropdown empty during transfer** | Less than two active accounts exist. | Ensure at least two accounts are created and set to `ACTIVE`. |

---

## 14. GitHub Repository & Contribution Workflow

**Remote Repository:** [https://github.com/RoshanAnandSeeli/VaultLedger.git](https://github.com/RoshanAnandSeeli/VaultLedger.git)

```bash
# 1. Clone repository
git clone https://github.com/RoshanAnandSeeli/VaultLedger.git

# 2. Verify build and run all 119 tests
mvn clean test

# 3. Launch the desktop application
mvn javafx:run
```

---

## 15. Academic Disclaimer

**VaultLedger** is developed solely for educational coursework and academic evaluation. It does not possess financial certifications, PCI-DSS compliance, or integration with real-world banking payment gateways. Do not use this software for processing real financial transactions.

---

*VaultLedger — Core Banking Account Lifecycle & Ledger System*  
*Repository: [https://github.com/RoshanAnandSeeli/VaultLedger](https://github.com/RoshanAnandSeeli/VaultLedger)*
