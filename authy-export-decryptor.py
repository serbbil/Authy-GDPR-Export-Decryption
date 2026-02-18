#!/usr/bin/env python3
import base64
import csv
import os
import sys
import io

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: Missing 'cryptography' library. Run: pip install cryptography")
    sys.exit(1)

def decrypt_account(row, password):
    try:
        backend = default_backend()
        password_bytes = password.encode('utf-8')
        
        data = {k.strip().lower(): v for k, v in row.items() if k}
        
        salt_raw = data.get('salt')
        iv_hex = data.get('iv')
        encrypted_b64 = data.get('encrypted_seed')
        
        if not salt_raw or not iv_hex or not encrypted_b64:
            return False, "Missing Data"

        salt_bytes = salt_raw.encode('utf-8')
        iv_bytes = bytes.fromhex(iv_hex.strip())
        encrypted_bytes = base64.b64decode(encrypted_b64.strip())

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
            backend=backend
        )
        key = kdf.derive(password_bytes)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_bytes) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        try:
            text = decrypted_data.decode('utf-8')
            clean_text = text.upper().replace('=', '').strip()
            
            # Case A: Plain Base32
            if all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567' for c in clean_text):
                return True, clean_text
            
            # Case B: Hex String
            if all(c in '0123456789abcdefABCDEF' for c in text.strip()):
                raw_bytes = bytes.fromhex(text.strip())
                return True, base64.b32encode(raw_bytes).decode('utf-8').replace('=', '')
        except:
            pass

        # Case C: Raw Bytes
        return True, base64.b32encode(decrypted_data).decode('utf-8').replace('=', '')

    except Exception as e:
        return False, str(e)

def parse_csv(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read().replace('"', '').replace("'", "")
        
        f_io = io.StringIO(content)
        try:
            dialect = csv.Sniffer().sniff(content[:1024], delimiters=',;')
            delimiter = dialect.delimiter
        except:
            delimiter = ','
            
        reader = csv.DictReader(f_io, delimiter=delimiter)
        if reader.fieldnames:
            reader.fieldnames = [h.strip().lower() for h in reader.fieldnames]
            
        return list(reader)
    except Exception as e:
        print(f"Error reading CSV: {e}")
        return []

def main():
    print("\n--- Authy GDPR Export Decryptor v1.0 ---\n")

    password = input("Backup Password: ")
    if not password: sys.exit(0)

    csv_path = input("CSV File Path: ").strip().replace('"', '').replace("'", "")
    if not os.path.exists(csv_path):
        print("Error: File not found.")
        sys.exit(1)

    rows = parse_csv(csv_path)
    if not rows: sys.exit(1)

    # Calculate column width
    max_len = 10
    valid_rows = []
    for r in rows:
        if 'encrypted_seed' in r or 'name' in r:
            name = r.get('name', 'Unknown')
            if len(name) > max_len: max_len = len(name)
            valid_rows.append(r)
    
    col_w = max_len + 2
    print(f"\n{'STATUS':<8} | {'ACCOUNT':<{col_w}} | {'TOTP SECRET'}")
    print("-" * (col_w + 45))

    success_count = 0
    for row in valid_rows:
        name = row.get('name', 'Unknown').strip()
        success, result = decrypt_account(row, password)
        
        status = "[ OK ]" if success else "[FAIL]"
        if success: success_count += 1
        
        print(f"{status:<8} | {name:<{col_w}} | {result}")

    print("-" * (col_w + 45))
    print(f"Decrypted: {success_count} / {len(valid_rows)}")
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
