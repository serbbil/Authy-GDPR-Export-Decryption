# Authy GDPR Export Decryption

> **Simple tool to decrypt Authy TOTP encrypted seeds provided by Twilio under GDPR legal request.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)

## 🛑 The Problem: Vendor Lock-in

If you use **Authy** for your 2FA, you might have noticed that **Twilio/Authy does not provide any option to export your tokens**. Unlike other authenticators (like Aegis, Raivo, or 2FAS), they keep your "secrets" locked inside their app. This forces you to either stay with them forever or manually disable and re-enable 2FA on every single service you use—a massive headache.

However, under **GDPR (General Data Protection Regulation)**, you have the right to data portability (Article 20). Twilio is legally required to provide your data if you ask for it correctly. The catch? They provide the TOTP seeds **encrypted** using your internal backup password, a unique salt, and an initialization vector (IV), making them unusable without decryption.

This tool automates the complex decryption process (AES-256-CBC + PBKDF2-HMAC-SHA1) to give you back your **plain text TOTP seeds**, allowing you to migrate to any other app.

---

## 🚀 Step 1: Request your Data (The Legal Way)

Since there is no export button, you must formally request your data from Twilio.

1.  Send an email to **`privacy@twilio.com`** (or `support@twilio.zendesk.com`).
2.  **Subject:** `GDPR Data Request - Authy Account Data Portability`
3.  **Body:** You can use the following template:

    > "I am writing to request a full export of my personal data associated with my Authy account under Article 20 of the GDPR (Right to Data Portability).
    >
    > Specifically, I require the **encrypted secret seeds** (TOTP tokens) for all accounts registered in my Authy app, along with the associated `salt` and `iv` values required to decrypt them."

4.  **Verification:** They will reply asking you to verify your identity. You must have access to:
    * The email address registered in Authy.
    * The phone number linked to the Authy account (they will send an SMS code).
5.  **The Wait:** Once verified, the process typically takes **up to 30 days**.

---

## 📂 Step 2: Prepare the Data

Twilio will eventually send you a secure file transfer link containing several CSVs. The one you need is usually named:
`Authy Personal Information Request - Exported Tokens (1).csv`

### Format Requirement
This tool requires a clean CSV format to work. Ensure your CSV file has **exactly** these headers in the first row. Twilio's export might be messy, so please open the file and ensure it matches this structure (including quotation marks):

**`Authy Personal Information Request - Exported Tokens (1).csv`**
```csv
"name,encrypted_seed,salt,iv
Amazon,aCQ2YpeAj9u5vj2Yxos...,Wo1dZyQXcBdH...,63cf7fdae59d...
Google,bHQ8XreBj1u9zj...,Po2dZyQXcBdX...,12af7fdbc59d..."
```

---

## 🛠️ Step 3: Usage

### Prerequisites
* **Python 3.x** installed.
* The `cryptography` library.

### Installation

1.  Clone this repository or download the script `authy-export-decryptor.py`.
2.  Install the required dependency via terminal:
    ```bash
    pip install cryptography
    ```

### Running the Decryptor

1.  Run the script:
    ```bash
    python authy-export-decryptor.py
    ```
2.  **Enter your Backup Password:**
    * ⚠️ **Important:** This is **NOT** your Twilio login password. It is the specific password you set inside the Authy App settings (under Accounts -> Backups) to encrypt your cloud tokens.
3.  **Provide the CSV:**
    * Drag and drop your prepared CSV file into the terminal window when prompted.

### Output
The script will attempt to decrypt every row using the correct encryption parameters (PBKDF2 100k iters, SHA1, AES-256). If successful, it will display a table with your accounts and the **TOTP Secret** ready to use.

```text
STATUS   | ACCOUNT                        | TOTP SECRET
-------------------------------------------------------------------------
[ OK ]   | Amazon AWS                     | JBSWY3DPEHPK3PXP
[ OK ]   | GitHub                         | NM4S4O3FGM2TKMRH
[FAIL]   | Old Account                    | Password incorrect or bad data
```



---

## ⚠️ Disclaimer

This tool is provided "as is" without warranty of any kind. It is intended for personal use to facilitate data portability as guaranteed by law (GDPR Article 20).

* Your **Backup Password** is never stored, sent, or logged anywhere; it is used only in memory to decrypt the seeds locally.
* **Security Tip:** Always protect your decrypted seeds. Delete them immediately after you have finished migrating your accounts to your new app.

---

## 📄 License

MIT License. Feel free to fork and contribute.
