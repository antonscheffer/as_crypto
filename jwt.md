You can use as_crypto to create or verify JWT's
* ES256
~~~
declare
  l_header    varchar2(1000);
  l_payload   varchar2(1000);
  l_signature varchar2(1000);
  l_sign   raw(1000);
  l_private_key varchar2(3999);
  l_public_key  varchar2(3999);
  --
  function base64URL_encode( p_src varchar2 )
  return varchar2
  is
  begin
    return translate( utl_raw.cast_to_varchar2( utl_encode.base64_encode( p_src ) ), '+/= ' || chr(10) || chr(13), '-_' ); 
  end;
  --
  function base64URL_decode( p_txt varchar2 )
  return raw
  is
  begin
    return utl_encode.base64_decode( utl_raw.cast_to_raw( translate( p_txt, '-_', '+/' ) ) ); 
  end;
begin
  l_header := base64URL_encode( utl_raw.cast_to_raw( '{"alg":"ES256","typ":"JWT"}' ) );
  l_payload := base64URL_encode( utl_raw.cast_to_raw( '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}' ) );
  l_private_key := utl_raw.cast_to_raw( '
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----' );
  l_public_key := utl_raw.cast_to_raw( '
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----' );
  l_sign := as_crypto.sign( utl_raw.cast_to_raw( l_header || '.' || l_payload )
                          , l_private_key
                          , as_crypto.KEY_TYPE_EC
                          , as_crypto.SIGN_SHA256withECDSAinP1363
                          );
  l_signature := base64URL_encode( l_sign );
  dbms_output.put_line( l_signature );
  if as_crypto.verify ( utl_raw.cast_to_raw( l_header || '.' || l_payload )
                      , base64URL_decode( l_signature )
                      , l_public_key
                      , as_crypto.KEY_TYPE_EC
                      , as_crypto.SIGN_SHA256withECDSAinP1363
                      )
  then
    dbms_output.put_line ('Verified');
  else
    dbms_output.put_line ('Failed verification');
  end if;
end;
~~~

* RS256
~~~
declare
  l_header    varchar2(1000);
  l_payload   varchar2(1000);
  l_signature varchar2(1000);
  l_sign   raw(1000);
  l_private_key varchar2(3999);
  l_public_key  varchar2(3999);
  --
  function base64URL_encode( p_src varchar2 )
  return varchar2
  is
  begin
    return translate( utl_raw.cast_to_varchar2( utl_encode.base64_encode( p_src ) ), '+/= ' || chr(10) || chr(13), '-_' ); 
  end;
  --
  function base64URL_decode( p_txt varchar2 )
  return raw
  is
  begin
    return utl_encode.base64_decode( utl_raw.cast_to_raw( translate( p_txt, '-_', '+/' ) ) ); 
  end;
begin
  l_header := base64URL_encode( utl_raw.cast_to_raw( '{"alg":"RS256","typ":"JWT"}' ) );
  l_payload := base64URL_encode( utl_raw.cast_to_raw( '{"sub":"1234567890","name":"John Doe","admin":true,"iat":1516239022}' ) );
  l_private_key := utl_raw.cast_to_raw( '
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----' );
  l_public_key := utl_raw.cast_to_raw( '
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----' );
  l_sign := as_crypto.sign( utl_raw.cast_to_raw( l_header || '.' || l_payload )
                          , l_private_key
                          , as_crypto.KEY_TYPE_RSA
                          , as_crypto.SIGN_SHA256_RSA
                          );
  l_signature := base64URL_encode( l_sign );
  dbms_output.put_line( l_signature );
  if as_crypto.verify ( utl_raw.cast_to_raw( l_header || '.' || l_payload )
                      , base64URL_decode( l_signature )
                      , l_public_key
                      , as_crypto.KEY_TYPE_RSA
                      , as_crypto.SIGN_SHA256_RSA
                      )
  then
    dbms_output.put_line ('Verified');
  else
    dbms_output.put_line ('Failed verification');
  end if;
end;
~~~

* HS256
~~~
  l_payload   varchar2(1000);
  l_signature varchar2(1000);
  l_sign   raw(1000);
  l_secret raw(1000);
  --
  function base64URL_encode( p_src varchar2 )
  return varchar2
  is
  begin
    return translate( utl_raw.cast_to_varchar2( utl_encode.base64_encode( p_src ) ), '+/= ' || chr(10) || chr(13), '-_' ); 
  end;
  --
  function base64URL_decode( p_txt varchar2 )
  return raw
  is
  begin
    return utl_encode.base64_decode( utl_raw.cast_to_raw( translate( p_txt, '-_', '+/' ) ) ); 
  end;
begin
  l_header := base64URL_encode( utl_raw.cast_to_raw( '{"alg":"HS256","typ":"JWT"}' ) );
  l_payload := base64URL_encode( utl_raw.cast_to_raw( '{"sub":"1234567890","name":"John Doe","iat":1516239022}' ) );
  l_secret := '571A910E9E061297F4A41FCDBF67C59DC2ABE04AA4FBFC166444B0FB3FF9498C';
  dbms_output.put_line( base64URL_encode( l_secret ) ); -- use this encoded value in the jwt.io debugger and check "secret base64 encoded
  l_sign := as_crypto.mac( utl_raw.cast_to_raw( l_header || '.' || l_payload )
                         , as_crypto.HMAC_SH256
                         , l_secret
                         );
  l_signature := base64URL_encode( l_sign );
  dbms_output.put_line( l_signature );
end;
~~~
