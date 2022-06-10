# as_crypto
A plsql implementation of some functions/procedures in dbms_crypto

This does include
* pkencrypt/pkdecrypt public/private key encryption/decryption with the following algorithms
  - RSA
* sign/verify using
  - SHA224 RSA
  - SHA256 RSA RSA_X391 withECDSA withECDSAinP1363
  - SHA384 RSA RSA_X391 withECDSA withECDSAinP1363
  - SHA512 RSA RSA_X391 withECDSA withECDSAinP1363
  - SHA1   RSA RSA_X391
* hash and mac function with the following algorithms
  - MD4
  - MD5
  - SH1
  - SH224
  - SH256
  - SH384
  - SH512
  - RIPEMD160
* encrypt/decrypt of raw values with the following algorithms
  - DES
  - 3DES_2KEY
  - 3DES
  - AES128
  - AES192
  - AES256
  - RC4

**Please note**:
This package will soon be included in https://github.com/OraOpenSource/oos-utils
~~All additions, changes and bugfixes only will be available at that repository.~~ The package at OraOpenSource will be an "independ" fork, I will continue to upgrade this package when needed.
