# Public HTTPS test fixtures

Original disposable test CA and localhost certificate, generated with Python cryptography. The PKCS8 private key is deliberately public and MUST NEVER be used outside isolated tests. SANs: localhost and 127.0.0.1. Validity: 2025-01-01 through 2040-01-01. The CA private key was discarded. No production trust store is modified.
