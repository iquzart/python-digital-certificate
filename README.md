# Digital Certificate Generator

[![Certificate Generator CI](https://github.com/iquzart/python-digital-certificate/actions/workflows/ci.yml/badge.svg)](https://github.com/iquzart/python-digital-certificate/actions/workflows/ci.yml)

### About
This script creates a self-signed CA and signed server/client certificates.

Version: 3
Encryption: SHA256 with RSA encryption (4096 bit)

### Security improvements
- Uses the actively maintained `cryptography` package instead of legacy `pyOpenSSL` bindings.
- Generates cryptographically secure certificate serial numbers.
- Encrypts generated private keys with a passphrase.
- Restricts private key file permissions to owner-only access.
- Sanitizes certificate output filenames to prevent path traversal.

Set `DIGITAL_CERT_PASSPHRASE` to avoid interactive passphrase prompts.

### Install

```bash
make install
```

### Create Certificate
CA certificate and key will be stored under the `CA` directory.

```bash
make run
```

### Sample output
```
Creating CA Certificate, please provide the values
Country Name (2 letter code) [XX]: AE
State or Province Name (full name) []: Dubai
Locality Name (eg, city) [Default City]: Emaar Square
Organization Name (eg, company) [Default Company Ltd]: XYZ Company
Organizational Unit Name (eg, section) []: Information Technology
Common Name (eg, your name or your server's hostname): XYZ Company SS CA
Email Address []: email@xyz.ae
Private key passphrase:
Confirm private key passphrase:
Created CA Certificate
CA Certificate valid for 3649 days
Client Certificate CN: svc1.xyz.ae
Private key passphrase:
Confirm private key passphrase:
Created client certificate: svc1.xyz.ae.crt
Created private key: svc1.xyz.ae.key
```
