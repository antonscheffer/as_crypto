declare
  procedure test( p_secret raw, p_type pls_integer, p_key raw, p_iv raw, p_txt varchar2 )
  is
    t_encr raw(32767);
  begin
    t_encr := as_crypto.encrypt( p_secret, p_type, p_key, p_iv );
    if t_encr != dbms_crypto.encrypt( p_secret, p_type, p_key, p_iv )
    then
      dbms_output.put_line( 'Difference encrypting ' || p_txt );
    end if;
    if p_secret != as_crypto.decrypt( t_encr, p_type, p_key, p_iv )
    then
      dbms_output.put_line( 'Difference decrypting ' || p_txt );
    end if;
  end;
--
  procedure test_mac( p_src raw, p_type pls_integer, p_key raw, p_txt varchar2 )
  is
    t_mac raw(3999);
  begin
    t_mac := as_crypto.mac( p_src, p_type, p_key );
    if t_mac != dbms_crypto.mac( p_src, p_type, p_key )
    then
      dbms_output.put_line( 'Difference for mac ' || p_txt );
    end if;
  end;
begin
  for i in 1 .. 18
  loop
    test( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
        , as_crypto.ENCRYPT_DES + as_crypto.CHAIN_CFB + as_crypto.PAD_NONE
        , utl_raw.cast_to_raw('12345678') -- 8 bytes
        , null
        , 'DES + CFB + NONE'
        );
    test( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
        , as_crypto.ENCRYPT_DES + as_crypto.CHAIN_CFB + as_crypto.PAD_PKCS5
        , utl_raw.cast_to_raw('12345678') -- 8 bytes
        , null
        , 'DES + CFB + PKCS5'
        );
    test( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
        , as_crypto.ENCRYPT_DES + as_crypto.CHAIN_CFB + as_crypto.PAD_ZERO
        , utl_raw.cast_to_raw('12345678') -- 8 bytes
        , null
        , 'DES + CFB + ZERO'
        );
    test( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
        , as_crypto.ENCRYPT_DES + as_crypto.CHAIN_CFB + as_crypto.PAD_ORCL
        , utl_raw.cast_to_raw('12345678') -- 8 bytes
        , null
        , 'DES + CFB + ORCL'
        );
  end loop;
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
        , as_crypto.ENCRYPT_DES + as_crypto.CHAIN_CFB + as_crypto.PAD_PKCS5
        , utl_raw.cast_to_raw('12345678') -- 8 bytes
        , null
        , 'DES + CBC + PKCS5'
        );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES_2KEY + as_crypto.CHAIN_CBC + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678') -- 18 bytes
      , null
      , '3DES_2KEY + CBC + PKCS5'
      );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES + as_crypto.CHAIN_CBC + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678ABCDEFGH') -- 24 bytes
      , null
      , '3DES + CBC + PKCS5'
      );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES + as_crypto.CHAIN_CBC + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678ABCDEFGH') -- 24 bytes
      , '567812345678ABCD' -- 8 bytes
      , '3DES + CBC + PKCS5 + IV'
      );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES + as_crypto.CHAIN_CFB + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678ABCDEFGH') -- 24 bytes
      , '567812345678ABCD' -- 8 bytes
      , '3DES + CFB + PKCS5 + IV'
      );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES + as_crypto.CHAIN_ECB + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678ABCDEFGH') -- 24 bytes
      , '567812345678ABCD' -- 8 bytes
      , '3DES + ECB + PKCS5 + IV'
      );
  test( utl_raw.cast_to_raw( '12345678ABCDEFGHIJ' ) -- 19 bytes
      , as_crypto.ENCRYPT_3DES + as_crypto.CHAIN_OFB + as_crypto.PAD_PKCS5
      , utl_raw.cast_to_raw('1234567812345678ABCDEFGH') -- 24 bytes
      , '567812345678ABCD' -- 8 bytes
      , '3DES + OFB + PKCS5 + IV'
      );
--
  for i in 1 .. 18
  loop
    test_mac( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
            , as_crypto.HMAC_MD5
            , utl_raw.cast_to_raw('12345678') -- 8 bytes
            , 'MD5, size ' || i
            );
    test_mac( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
            , as_crypto.HMAC_SH1
            , utl_raw.cast_to_raw('12345678') -- 8 bytes
            , 'SH1, size ' || i
            );
$IF NOT DBMS_DB_VERSION.VER_LE_11 $THEN
    test_mac( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
            , as_crypto.HMAC_SH256
            , utl_raw.cast_to_raw('12345678') -- 8 bytes
            , 'SH256, size ' || i
            );
    test_mac( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
            , as_crypto.HMAC_SH384
            , utl_raw.cast_to_raw('12345678') -- 8 bytes
            , 'SH384, size ' || i
            );
    test_mac( utl_raw.substr( utl_raw.cast_to_raw( '0123456789ABCDEFGH987654321' ), 1, i )
            , as_crypto.HMAC_SH512
            , utl_raw.cast_to_raw('12345678') -- 8 bytes
            , 'SH512, size ' || i
            );
$END
  end loop;
end;
