create or replace package as_crypto
is
/*
MIT License

Copyright (c) 2016-2022 Anton Scheffer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
    -- Hash Functions
    HASH_MD4           CONSTANT PLS_INTEGER            :=     1;
    HASH_MD5           CONSTANT PLS_INTEGER            :=     2;
    HASH_SH1           CONSTANT PLS_INTEGER            :=     3;
    HASH_SH256         CONSTANT PLS_INTEGER            :=     4;
    HASH_SH384         CONSTANT PLS_INTEGER            :=     5;
    HASH_SH512         CONSTANT PLS_INTEGER            :=     6;
    HASH_SH224         CONSTANT PLS_INTEGER            :=     11;
    HASH_SH512_224     CONSTANT PLS_INTEGER            :=     12;
    HASH_SH512_256     CONSTANT PLS_INTEGER            :=     13;
    HASH_MD2           CONSTANT PLS_INTEGER            :=     14;
    HASH_RIPEMD160     CONSTANT PLS_INTEGER            :=     15;
    -- MAC Functions
    HMAC_MD5           CONSTANT PLS_INTEGER            :=     1;
    HMAC_SH1           CONSTANT PLS_INTEGER            :=     2;
    HMAC_SH256         CONSTANT PLS_INTEGER            :=     3;
    HMAC_SH384         CONSTANT PLS_INTEGER            :=     4;
    HMAC_SH512         CONSTANT PLS_INTEGER            :=     5;
    HMAC_MD4           CONSTANT PLS_INTEGER            :=     10;
    HMAC_SH224         CONSTANT PLS_INTEGER            :=     11;
    HMAC_SH512_224     CONSTANT PLS_INTEGER            :=     12;
    HMAC_SH512_256     CONSTANT PLS_INTEGER            :=     13;
    HMAC_RIPEMD160     CONSTANT PLS_INTEGER            :=     14;
    -- Block Cipher Algorithms
    ENCRYPT_DES        CONSTANT PLS_INTEGER            :=     1;  -- 0x0001
    ENCRYPT_3DES_2KEY  CONSTANT PLS_INTEGER            :=     2;  -- 0x0002
    ENCRYPT_3DES       CONSTANT PLS_INTEGER            :=     3;  -- 0x0003
    ENCRYPT_AES        CONSTANT PLS_INTEGER            :=     4;  -- 0x0004
    ENCRYPT_PBE_MD5DES CONSTANT PLS_INTEGER            :=     5;  -- 0x0005
    ENCRYPT_AES128     CONSTANT PLS_INTEGER            :=     6;  -- 0x0006
    ENCRYPT_AES192     CONSTANT PLS_INTEGER            :=     7;  -- 0x0007
    ENCRYPT_AES256     CONSTANT PLS_INTEGER            :=     8;  -- 0x0008
    -- Block Cipher Chaining Modifiers
    CHAIN_CBC          CONSTANT PLS_INTEGER            :=   256;  -- 0x0100
    CHAIN_CFB          CONSTANT PLS_INTEGER            :=   512;  -- 0x0200
    CHAIN_ECB          CONSTANT PLS_INTEGER            :=   768;  -- 0x0300
    CHAIN_OFB          CONSTANT PLS_INTEGER            :=  1024;  -- 0x0400
    CHAIN_GCM          CONSTANT PLS_INTEGER            :=  1280;  -- 0x0500
    CHAIN_OFB_REAL     CONSTANT PLS_INTEGER            :=  2560;  -- 0x0A00
   -- Block Cipher Padding Modifiers
    PAD_PKCS5          CONSTANT PLS_INTEGER            :=  4096;  -- 0x1000
    PAD_NONE           CONSTANT PLS_INTEGER            :=  8192;  -- 0x2000
    PAD_ZERO           CONSTANT PLS_INTEGER            := 12288;  -- 0x3000
    PAD_ORCL           CONSTANT PLS_INTEGER            := 16384;  -- 0x4000
    PAD_OneAndZeroes   CONSTANT PLS_INTEGER            := 20480;  -- 0x5000
    PAD_ANSI_X923      CONSTANT PLS_INTEGER            := 24576;  -- 0x6000
    -- Stream Cipher Algorithms
    ENCRYPT_RC4        CONSTANT PLS_INTEGER            :=   129;  -- 0x0081
    -- Public Key Encryption Algorithm
    PKENCRYPT_RSA_PKCS1_OAEP      constant pls_integer := 1;
    PKENCRYPT_RSA_PKCS1_OAEP_SHA2 constant pls_integer := 2;
    -- Public Key Type Algorithm
    KEY_TYPE_RSA   constant pls_integer := 1;
    KEY_TYPE_EC    constant pls_integer := 2;
    KEY_TYPE_EdDSA constant pls_integer := 3;
    -- Public Key Signature Type Algorithm
    SIGN_SHA224_RSA             constant pls_integer := 1;   -- SHA 224 bit hash function with RSA
    SIGN_SHA256_RSA             constant pls_integer := 2;   -- SHA 256 bit hash function with RSA
    SIGN_SHA256_RSA_X931        constant pls_integer := 3;   -- SHA 256 bit hash function with RSA and X931 padding
    SIGN_SHA384_RSA             constant pls_integer := 4;   -- SHA 384 bit hash function with RSA
    SIGN_SHA384_RSA_X931        constant pls_integer := 5;   -- SHA 384 bit hash function with RSA and X931 padding
    SIGN_SHA512_RSA             constant pls_integer := 6;   -- SHA 512 bit hash function with RSA
    SIGN_SHA512_RSA_X931        constant pls_integer := 7;   -- SHA 512 bit hash function with RSA and X931 padding
    SIGN_SHA1_RSA               constant pls_integer := 8;   -- SHA1 hash function with RSA
    SIGN_SHA1_RSA_X931          constant pls_integer := 9;   -- SHA1 hash function with RSA and X931 padding
    SIGN_MD2_RSA                constant pls_integer := 20;  -- MD2 hash function with RSA
    SIGN_MD5_RSA                constant pls_integer := 21;  -- MD2 hash function with RSA
    SIGN_SHA256withECDSA        constant pls_integer := 10;
    SIGN_SHA256withECDSAinP1363 constant pls_integer := 11;
    SIGN_SHA384withECDSA        constant pls_integer := 12;
    SIGN_SHA384withECDSAinP1363 constant pls_integer := 13;
    SIGN_SHA512withECDSA        constant pls_integer := 14;
    SIGN_SHA512withECDSAinP1363 constant pls_integer := 15;
    SIGN_Ed25519                constant pls_integer := 16;
    SIGN_SHA256_RSA_PSS         constant pls_integer := 17;  -- SHA 256 bit hash function with RSASSA-PSS
    SIGN_SHA384_RSA_PSS         constant pls_integer := 18;  -- SHA 384 bit hash function with RSASSA-PSS
    SIGN_SHA512_RSA_PSS         constant pls_integer := 19;  -- SHA 512 bit hash function with RSASSA-PSS
--
  function hash( src raw, typ pls_integer )
  return raw;
--
  function mac( src raw, typ pls_integer, key raw )
  return raw;
--
  function randombytes( number_bytes positive )
  return raw;
--
  function encrypt( src raw, typ pls_integer, key raw, iv raw := null )
  return raw;
--
  function decrypt( src raw, typ pls_integer, key raw, iv raw := null )
  return raw;
--
  function encrypt( src in  raw
                  , typ in  pls_integer
                  , key in  raw
                  , iv  in  raw := null
                  , aad in  raw := null
                  , tag out raw
                  )
  return raw;
  --
  function decrypt( src in raw
                  , typ in pls_integer
                  , key in raw
                  , iv  in raw := null
                  , aad in raw := null
                  , tag in raw
                  )
  return raw;
  --
  function pkEncrypt( src raw
                    , pub_key raw
                    , pubkey_alg binary_integer
                    , enc_alg binary_integer
                    )
  return raw;
--
  function pkDecrypt( src raw
                    , prv_key raw
                    , pubkey_alg binary_integer
                    , enc_alg binary_integer
                    )
  return raw;
--
  function sign( src raw
               , prv_key raw
               , pubkey_alg binary_integer
               , sign_alg binary_integer
               )
  return raw;
--
  function verify( src raw
                 , sign raw
                 , pub_key raw
                 , pubkey_alg binary_integer
                 , sign_alg binary_integer
                 )
  return boolean;
end;
/

create or replace package body as_crypto
is
--
  c_X931_TRAILER_SH1   constant raw(2) := '33CC';
  c_X931_TRAILER_SH224 constant raw(2) := '38CC';
  c_X931_TRAILER_SH256 constant raw(2) := '34CC';
  c_X931_TRAILER_SH384 constant raw(2) := '36CC';
  c_X931_TRAILER_SH512 constant raw(2) := '35CC';
--
  c_ASN1_MD2   raw(100) := '3020300C06082A864886F70D020205000410';
  c_ASN1_MD5   raw(100) := '3020300C06082A864886F70D020505000410';
  c_ASN1_SH1   raw(100) := '3021300906052B0E03021A05000414';
  c_ASN1_SH224 raw(100) := '302D300D06096086480165030402040500041C';
  c_ASN1_SH256 raw(100) := '3031300D060960864801650304020105000420';
  c_ASN1_SH384 raw(100) := '3041300D060960864801650304020205000430';
  c_ASN1_SH512 raw(100) := '3051300D060960864801650304020305000440';
--
  c_INTEGER    raw(1) := '02';
  c_BIT_STRING raw(1) := '03';
  c_OCTECT     raw(1) := '04';
  c_NULL       raw(1) := '05';
  c_OID        raw(1) := '06';
  c_SEQUENCE   raw(1) := '30';
  type tp_key_parameters is table of raw(3999) index by pls_integer;
--
  type tp_mag is table of number index by pls_integer;
  ccc number := 16; -- number of nibbles
  cm number := power( 16, ccc );
  cmm number := cm - 1;
  cm2 number := cm / 2;
  cmi number := power( 16, -ccc );
  --
  function mag( p1 varchar2 )
  return tp_mag;
  --
  c_mag_0 constant tp_mag := mag( '0' );
  c_mag_1 constant tp_mag := mag( '1' );
  c_mag_3 constant tp_mag := mag( '3' );
  c_mag_4 constant tp_mag := mag( '4' );
--
  type tp_ec_point is record
    ( x tp_mag
    , y tp_mag
    , z tp_mag
    );
  type tp_ec_curve is record
    ( prime tp_mag
    , group_order tp_mag
    , a tp_mag
    , b tp_mag
    , p_plus_1_div_4 tp_mag
    , generator tp_ec_point
    , nlen pls_integer
    );
  type tp_ed_point is record
    ( x tp_mag
    , y tp_mag
    , z tp_mag
    , t tp_mag
    );
  type tp_ed_curve is record
    ( nlen pls_integer
    , l tp_mag
    , d tp_mag
    , q tp_mag
    , i tp_mag
    , b tp_ed_point
    );
  --
  bmax32 constant number := power( 2, 32 ) - 1;
  bmax64 constant number := power( 2, 64 ) - 1;
  type tp_crypto is table of number;
  type tp_aes_tab is table of number index by pls_integer;
--
  SP1 tp_crypto;
  SP2 tp_crypto;
  SP3 tp_crypto;
  SP4 tp_crypto;
  SP5 tp_crypto;
  SP6 tp_crypto;
  SP7 tp_crypto;
  SP8 tp_crypto;
--
  function mag( p1 varchar2 )
  return tp_mag
  is
    l number;
    n number;
    rv tp_mag;
    t1 varchar2(3999);
    cfmt1 varchar2(100) := rpad( 'X', ccc, 'X' );
  begin
    t1 := nvl( ltrim( p1, '0' ), '0' );
    l := ceil( length( t1 ) / ccc );
    t1 := lpad( t1, l * ccc, '0' );
    for i in 0 .. l - 1
    loop
      n := to_number( substr( t1, 1 + i * ccc, ccc ), cfmt1 );
      rv( l - 1 - i ) := n;
    end loop;
    return rv;
  end;
--
  function demag( p1 tp_mag )
  return varchar2
  is
    rv varchar2(3999);
    cfmt2 varchar2(100);
  begin
    if ccc = 1
    then
      cfmt2 := 'fmx';
    else
      cfmt2 := 'fm' || rpad( '0', ccc, 'x' );
    end if;
    for i in 0 .. p1.count - 1
    loop
      rv := to_char( p1( i ), cfmt2 ) || rv;
    end loop;
    return nvl( ltrim( rv, '0' ), '0' );
  end;
  --
  function requal( x tp_mag, y tp_mag )
  return boolean
  is
    rv boolean;
  begin
    if x.count != y.count
    then
      return false;
    end if;
    for i in 0 .. x.count - 1
    loop
      rv := x(i) = y(i);
      exit when not rv;
    end loop;
    return rv;
  end;
  --
  function r_greater_equal( x tp_mag, y tp_mag )
  return boolean
  is
    rv boolean := true;
    xc pls_integer := x.count;
    yc pls_integer := y.count;
  begin
    if xc > yc
    then
      return true;
    elsif xc < yc
    then
      return false;
    end if;
    for i in reverse 0 .. xc - 1
    loop
      exit when x(i) > y(i);
      if x(i) < y(i)
      then
        rv := false;
        exit;
      end if;
    end loop;
    return rv;
  end;
  --
  function radd( x tp_mag, y tp_mag )
  return tp_mag
  is
    c number;
    t number;
    rv tp_mag;
    xc pls_integer := x.count;
    yc pls_integer := y.count;
  begin
    if xc < yc
    then
      return radd( y, x );
    end if;
    c := 0;
    for i in 0 .. yc - 1
    loop
      t := x(i) + y(i) + c;
      if t >= cm
      then
        t := t - cm;
        c := 1;
      else
        c := 0;
      end if;
      rv(i) := t;
    end loop;
    for i in yc .. xc - 1
    loop
      t := x(i) + c;
      if t >= cm
      then
        t := t - cm;
        c := 1;
      else
        c := 0;
      end if;
      rv(i) := t;
    end loop;
    if c > 0
    then
      rv( xc ) := 1;
    end if;
    return rv;
  end;
  --
  function rsub( p1 tp_mag, p2 tp_mag )
  return tp_mag
  is
    b number;
    t number;
    rv tp_mag;
  begin
    b := 0;
    for i in 0 .. p2.count - 1
    loop
      t := p1( i ) - p2( i ) - b;
      if t < 0
      then
        b := 1;
        t := t + cm;
      else
        b := 0;
      end if;
      rv( i ) := t;
    end loop;
    for i in p2.count .. p1.count - 1
    loop
      t := p1( i ) - b;
      if t < 0
      then
        b := 1;
        t := t + cm;
      else
        b := 0;
      end if;
      rv( i ) := t;
    end loop;
    while rv( rv.last ) = 0 and rv.count > 1
    loop
      rv.delete( rv.last );
    end loop;
    if rv.count = 0
    then
      rv(0) := 0;
    end if;
    return rv;
  end;
  --
  function nsub( x tp_mag, y number )
  return tp_mag
  is
    b number;
    s tp_mag := x;
  begin
    b := y;
    for i in 0 .. s.count - 1
    loop
      s( i ) := s( i ) - b;
      if s( i ) < 0
      then
        b := 1;
        s( i ) := s( i ) + cm;
      else
        exit;
      end if;
    end loop;
    return s;
  end;
  --
  function nmul( x tp_mag, y number )
  return tp_mag
  is
    t number;
    c number := 0;
    rv tp_mag := x;
  begin
    for i in 0 .. rv.count - 1
    loop
      t := rv(i) * y + c;
      c := trunc( t * cmi );
      rv(i) := t - c * cm;
    end loop;
    if c > 0
    then
      rv(rv.count) := c;
    end if;
    return rv;
  end;
  --
  function rmul( x tp_mag, y tp_mag )
  return tp_mag
  is
    t number;
    c number;
    ci pls_integer;
    m tp_mag;
  begin
    for i in 0 .. y.count + x.count - 2
    loop
      m(i) := 0;
    end loop;
    for yi in 0 .. y.count - 1
    loop
      c := 0;
      for xi in 0 .. x.count - 1
      loop
        ci := xi+yi;
        t := m(ci) + x(xi) * y(yi) + c;
        c := trunc( t * cmi );
        m(ci) := t - c * cm;
      end loop;
      if c > 0
      then
        m( ci + 1 ) := c;
      end if;
    end loop;
    return m;
  end;
  --
  function xmod( x tp_mag, y tp_mag )
  return tp_mag
  is
    xc number := x.count;
    yc number := y.count;
    rv tp_mag;
    ly tp_mag;
    dq tp_mag;
    l_gt boolean;
    d number;
    d2 number;
    tmp number;
    r number;
    sf number;
    --
    procedure sub( x in out tp_mag, y tp_mag, p number )
    is
      b number := 0;
    begin
      for i in p .. p + y.count - 1
      loop
        x(i) := x(i) - y( i - p ) - b;
        if x(i) < 0
        then
          x(i) := x(i) + cm;
          b := 1;
        else
          b := 0;
        end if;
      end loop;
    end;
    --
    function ge( x tp_mag, y tp_mag, p number )
    return boolean
    is
      l_ge boolean := true;
    begin
      for i in reverse p .. p + y.count - 1
      loop
        case standard.sign( x(i) - y( i - p ) )
          when 1 then
            exit;
          when -1 then
            l_ge := false;
            exit;
          else null;
        end case;
      end loop;
      return l_ge;
    end;
  --
  begin
    if xc < yc
    then
      return x;
    end if;
    if xc = yc
    then
      for i in reverse 0 .. xc - 1
      loop
        if x( i ) > y( i )
        then
          l_gt := true;
          exit;
        elsif x( i ) < y( i )
        then
          return x;
        end if;
      end loop;
      if l_gt is null
      then
        rv(0) := 0;
      end if;
    end if;
    if yc > 1
    then
      ly := y;
      if y( yc - 1 ) < cm2
      then
        sf := trunc( cm / ( y( yc - 1 ) + 1 ) );
        r := 0;
        for i in 0 .. xc - 1
        loop
          tmp := x(i) * sf + r;
          if tmp < cm
          then
            r := 0;
            rv(i) := tmp;
          else
            r := trunc( tmp * cmi );
            rv(i) := tmp - r * cm;
          end if;
        end loop;
        if r > 0
        then
          rv(xc) := r;
          xc := xc + 1;
        end if;
        --
        r := 0;
        for i in 0 .. yc - 1
        loop
          tmp := ly(i) * sf + r;
          if tmp < cm
          then
            r := 0;
            ly(i) := tmp;
          else
            r := trunc( tmp * cmi );
            ly(i) := tmp - r * cm;
          end if;
        end loop;
      else
        rv := x;
      end if;
      if xc = 2
      then
        rv(2) := 0;
        xc := 3;
      end if;
      --
      if ge( rv, ly, xc - yc )
      then
        sub( rv, ly, xc - yc );
      end if;
      --
      d2 := ly( yc - 1 ) * cm + ly( yc - 2 );
      for i in reverse yc .. xc - 1
      loop
        if rv(i) > 0
        then
          if rv(i) > d2
          then
            d := cm - 1;
          else
            tmp := rv(i) * cm + rv( i - 1 );
            if tmp > d2
            then
              d := cm - 1;
            else
              d := least( trunc( cm * ( tmp / d2 ) + rv( i - 2 ) / d2 ), cm - 1 );
            end if;
          end if;
          dq.delete;
          r := 0;
          for j in 0 .. yc - 1
          loop
            tmp := ly(j) * d + r;
            if tmp < cm
            then
              r := 0;
              dq(j) := tmp;
            else
              r := trunc( tmp * cmi );
              dq(j) := tmp - r * cm;
            end if;
          end loop;
          dq( yc ) := r;
          if not ge( rv, dq, i - yc )
          then
            r := 0;
            for j in 0 .. yc - 1
            loop
              tmp := dq(j);
              tmp := tmp - ly(j) - r;
              if dq(j) < 0
              then
                dq(j) := tmp + cm;
                r := 1;
              else
                dq(j) := tmp;
                r := 0;
              end if;
            end loop;
            if r > 0
            then
              dq(yc) := dq(yc) - 1;
            end if;
          end if;
          sub( rv, dq, i - yc );
        end if;
      end loop;
      --
      --   if rv >= ly then substract ly from rv
      if ge( rv, ly, 0 )
      then
        sub( rv, ly, 0 );
      end if;
      --
      for i in reverse 1 .. xc - 1
      loop
        exit when rv(i) > 0;
        rv.delete(i);
      end loop;
    --
    else
      d := y(0);
      r := 0;
      if d > 1
      then
        for i in reverse 0 .. x.count - 1
        loop
          tmp := r * cm + x(i);
          r := tmp - trunc( tmp / d ) * d;
        end loop;
      end if;
      rv(0) := r;
    end if;
    if sf is not null
    then
      r := 0;
      for i in reverse 0 .. rv.count - 1
      loop
        tmp := rv(i) + r * cm;
        rv(i) := trunc( tmp / sf );
        r := tmp - rv(i) * sf;
      end loop;
      tmp := rv.count - 1;
      if tmp > 0 and rv( tmp ) = 0
      then
        rv.delete( tmp );
      end if;
    end if;
    return rv;
  end;
  --
  function addmod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
    rv tp_mag := radd( p1, p2 );
  begin
    if r_greater_equal( rv, m )
    then
      rv := rsub( rv, m );
    end if;
    return rv;
  end;
  --
  function submod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
    rv tp_mag := radd( p1, rsub( m, p2 ) );
  begin
    if r_greater_equal( rv, m )
    then
      rv := rsub( rv, m );
    end if;
    return rv;
  end;
  --
  function mulmod( p1 tp_mag, p2 tp_mag, m tp_mag )
  return tp_mag
  is
  begin
    return xmod( rmul( p1, p2 ), m );
  end;
  --
  function small_nmulmod( p1 tp_mag, n number, m tp_mag )
  return tp_mag
  is
    rv tp_mag := nmul( p1, n );
  begin
    for i in 1 .. 5  -- expect n < 5
    loop
      exit when not r_greater_equal( rv, m );
      if i = 5
      then
        rv := xmod( rv, m );
      else
        rv := rsub( rv, m );
      end if;
    end loop;
    return rv;
  end;
  --
  function rdiv2( p1 tp_mag )
  return tp_mag
  is
    c number;
    t number;
    rv tp_mag;
  begin
    if p1.count = 1
    then
      rv(0) := trunc( p1( 0 ) / 2 );
    else
      c := 0;
      for i in reverse 0 .. p1.count - 1
      loop
        t := p1( i ) + c;
        rv( i ) := trunc( t / 2 );
        c := case when bitand( t, 1 ) = 1 then cm else 0 end;
      end loop;
      while rv( rv.last ) = 0
      loop
        rv.delete( rv.last );
      end loop;
    end if;
    return rv;
  end;
  --
  function powmod( pa tp_mag, pb tp_mag, pm tp_mag )
  return tp_mag
  is
    m1 tp_mag;
    r tp_mag;
    k pls_integer;
    mc pls_integer;
    ninv0 number;
    bx0 number;
    mx0 number;
    nx number;
    xx number;
    xm tp_mag;
    am tp_mag;
    one tp_mag;
    tx varchar2(3999);
    sb varchar2(3999);
    nr number;
    hb boolean := false;
    function monpro( pa tp_mag, pb tp_mag )
    return tp_mag
    is
      b number;
      c number;
      m number;
      tmp number;
      t0 number;
      t tp_mag;
      ta tp_mag;
      tb tp_mag;
    begin
      ta := pa;
      for i in ta.count .. mc - 1
      loop
        ta( i ) := 0;
      end loop;
      tb := pb;
      for i in tb.count .. mc - 1
      loop
        tb( i ) := 0;
      end loop;
      for i in 0 .. mc
      loop
        t( i ) := 0;
      end loop;
      for i in 0 .. mc - 1
      loop
        t( mc + 1 ) := 0;
        tmp := t(0) + ta(0) * tb( i );
        c := trunc( tmp * cmi );
        t0 := tmp - c * cm;
        t(1) := t(1) + c;
        tmp := t0 * ninv0;
        m := tmp - trunc( tmp * cmi ) * cm;
        tmp := t0 + m * m1(0);
        if tmp >= cm
        then
          t(1) := t(1) + trunc( tmp * cmi );
        end if;
        -- check for overflow of t(1)?
        for j in 1 .. mc - 1
        loop
          tmp := t( j ) + ta( j ) * tb( i ) + m * m1( j );
          if tmp >= cm
          then
            c := trunc( tmp * cmi );
            t( j - 1 ) := tmp - c * cm;
            if c >= cm
            then
              c := c - cm;
              t( j + 2 ) := t( j + 2 ) + 1;
            end if;
            t( j + 1 ) := t( j + 1 ) + c;
          else
            t( j - 1 ) := tmp;
          end if;
        end loop;
        t( mc - 1 ) := t( mc );
        t( mc ) := t( mc + 1 );
      end loop;
      t.delete(mc+1);
      for j in reverse 1 .. t.count - 1
      loop
        exit when t(j) > 0;
        t.delete(j);
      end loop;
      b := t.count - mc;
      if b = 0
      then
        for i in reverse 0 .. mc - 1
        loop
          b := t(i) - m1(i);
          exit when b != 0;
        end loop;
        if b = 0
        then
          t.delete;
          t(0) := 0;
        end if;
      end if;
      if b > 0
      then
        b := 0;
        for i in 0 .. mc - 1
        loop
          tmp := t(i) - m1(i) - b;
          if tmp < 0
          then
            b := 1;
            t(i) := tmp + cm;
          else
            b := 0;
            t(i) := tmp;
          end if;
        end loop;
        for i in mc .. t.count - 1
        loop
          tmp := t(i) - b;
          if tmp < 0
          then
            b := 1;
            t(i) := tmp + cm;
          else
            t(i) := tmp;
            exit;
          end if;
        end loop;
        for j in reverse 1 .. t.count - 1
        loop
          exit when t(j) > 0;
          t.delete(j);
        end loop;
      end if;
      return t;
    end;
  begin
    m1 := pm;
    mc := m1.count;
    k := mc * ccc * 4;
    for i in 0 .. mc - 1
    loop
      r( i ) := 0;
    end loop;
    r( mc ) := 1;
    -- See "A New Algorithm for Inversion mod pk", Cetin Kaya Koc, https://eprint.iacr.org/2017/411.pdf
    bx0 := m1(0);
    mx0 := 2 * bx0;
    if mx0 >= cm
    then
      mx0 := mx0 - cm;
    end if;
    nx := 1;
    for j in 1 .. ccc * 4 - 1
    loop
      xx := bitand( bx0, power( 2, j ) );
      if xx > 0
      then
        nx := nx + xx;
        bx0 := bx0 + mx0;
        if bx0 >= cm
        then
          bx0 := bx0 - cm;
        end if;
      end if;
      mx0 := 2 * mx0;
      if mx0 >= cm
      then
        mx0 := mx0 - cm;
      end if;
    end loop;
    ninv0 := cm - nx;
    --
    xm := xmod( r, m1 );
    am := xmod( rmul( pa, xm ), m1 );
    sb := nvl( ltrim( demag( pb ), '0' ), '0' );
    for i in 1 .. length( sb )
    loop
      nr := to_number( substr( sb, i, 1 ), 'x' );
      for j in reverse 0 .. 3
      loop
        if not hb and bitand( nr, power( 2, j ) ) > 0
        then
          hb := true;
        end if;
        if hb
        then
          xm := monpro( xm, xm );
        end if;
        if bitand( nr, power( 2, j ) ) > 0
        then
          xm := monpro( am, xm );
        end if;
      end loop;
    end loop;
    one(0) := 1;
    return monpro( xm, one);
  end;
  --
  procedure get_named_ed_curve( p_name in varchar2, p_curve out tp_ed_curve )
  is
  begin
    if p_name in ( 'ed25519', 'ssh-ed25519' )
    then
      p_curve.nlen := 32;  -- b / 8
      p_curve.l := mag( '1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed' );   -- prime order 2^252 + 27742317777372353535851937790883648493
      p_curve.d := mag( '52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3' );   -- -121665/121666 = 37095705934669439343138083508754565189542113879843219016388785533085940283555
      p_curve.q := mag( '7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed' );   -- 2^255 - 19  (mod 2^256)
      p_curve.i := mag( '2B8324804FC1DF0B2B4D00993DFBD7A72F431806AD2FE478C4EE1B274A0EA0B0' );   -- sqrt(-1) mod q
      p_curve.b.x := mag( '216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A' ); -- 15112221349535400772501151409588531511454012693041857206046113283949847762202
      p_curve.b.y := mag( '6666666666666666666666666666666666666666666666666666666666666658' ); -- 46316835694926478169428394003475163141307993866256225615783033603165251855960
      p_curve.b.z := c_mag_1;
      p_curve.b.t := mag( '67875F0FD78B766566EA4E8E64ABE37D20F09F80775152F56DDE8AB3A5B7DDA3' );
    end if;
  end;
  --
  procedure get_named_curve( p_name in varchar2, p_curve out tp_ec_curve )
  is
  begin
    if p_name = 'nistp256'
    then
      p_curve.nlen := 32;
      p_curve.prime          := mag( 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff' );
      p_curve.group_order    := mag( 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551' );
      p_curve.a              := mag( 'ffffffff00000001000000000000000000000000fffffffffffffffffffffffc' );
      p_curve.b              := mag( '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b' );
      p_curve.generator.x    := mag( '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296' );
      p_curve.generator.y    := mag( '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5' );
      p_curve.p_plus_1_div_4 := mag( '3fffffffc0000000400000000000000000000000400000000000000000000000' );
    elsif p_name = 'nistp384'
    then
      p_curve.nlen := 48;
      p_curve.prime          := mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff' );
      p_curve.group_order    := mag( 'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973' );
      p_curve.a              := mag( 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc' );
      p_curve.b              := mag( 'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef' );
      p_curve.generator.x    := mag( 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7' );
      p_curve.generator.y    := mag( '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f' );
      p_curve.p_plus_1_div_4 := mag( '3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc00000000000000040000000' );
    elsif p_name = 'nistp521'
    then
      p_curve.nlen := 66;
      p_curve.prime          := mag( '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' );
      p_curve.group_order    := mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409' );
      p_curve.a              := mag( '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc' );
      p_curve.b              := mag( '51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00' );
      p_curve.generator.x    := mag( 'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66' );
      p_curve.generator.y    := mag( '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650' );
      p_curve.p_plus_1_div_4 := mag( '8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' );
    end if;
  end;
  --
  procedure bytes_to_ec_point( p_bytes raw, p_curve tp_ec_curve, p_point out tp_ec_point )
  is
    l_first varchar2(2);
    l_y2 tp_mag;
  begin
    l_first := utl_raw.substr( p_bytes, 1, 1 );
    if not (  ( l_first = '04' and utl_raw.length( p_bytes ) = 1 + 2 * p_curve.nlen )
           or ( l_first in ( '02', '03' ) and utl_raw.length( p_bytes ) = 1 + p_curve.nlen )
           )
    then
      raise_application_error( -20024, 'invalid encoded EC point.' );
    end if;
    if l_first = '04'
    then
      p_point.x := mag( utl_raw.substr( p_bytes, 2, p_curve.nlen ) );
      p_point.y := mag( utl_raw.substr( p_bytes, 2 + p_curve.nlen, p_curve.nlen ) );
      -- check if it's a point on the curve
      if not requal( addmod( addmod( powmod( p_point.x, mag( '3' ), p_curve.prime )
                                   , mulmod( p_point.x, p_curve.a, p_curve.prime )
                                   , p_curve.prime
                                   )
                           , p_curve.b
                           , p_curve.prime
                           )
                   , mulmod( p_point.y, p_point.y, p_curve.prime )
                   )
      then
        raise_application_error( -20025, 'EC Point is not on EC Curve.' );
      end if;
    else
      -- see https://tools.ietf.org/id/draft-jivsov-ecc-compact-05.html
      p_point.x := mag( utl_raw.substr( p_bytes, 2, p_curve.nlen ) );
      l_y2 := addmod( addmod( powmod( p_point.x, mag( '3' ), p_curve.prime )
                            , mulmod( p_point.x, p_curve.a, p_curve.prime )
                            , p_curve.prime
                            )
                    , p_curve.b
                    , p_curve.prime
                    );
      p_point.y := powmod( l_y2, p_curve.p_plus_1_div_4, p_curve.prime );
      if to_number( l_first ) - 2 != mod( p_point.y( 0 ), 2 )
      then
        p_point.y := rsub( p_curve.prime, p_point.y );
      end if;
      -- raise_application_error( -20023, 'EC Point compression not supported.' );
    end if;
  end;
  --
  function from_jacobian( p_point tp_ec_point, p_curve tp_ec_curve )
  return tp_ec_point
  is
    l_inv tp_mag;
    l_tmp tp_mag;
    l_rv tp_ec_point;
  begin
    if p_point.z(0) = 1 and p_point.z.count = 1
    then
      l_rv.x := p_point.x;
      l_rv.y := p_point.y;
    elsif p_point.y(0) = 0 and p_point.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
    else
      l_inv := powmod( p_point.z, nsub( p_curve.prime, 2 ), p_curve.prime );
      l_tmp := mulmod( l_inv, l_inv, p_curve.prime );
      l_rv.x := mulmod( p_point.x, l_tmp, p_curve.prime );
      l_rv.y := mulmod( p_point.y, mulmod( l_tmp, l_inv, p_curve.prime ), p_curve.prime );
    end if;
    return l_rv;
  end;
  --
  function to_jacobian( p_point tp_ec_point )
  return tp_ec_point
  is
    l_rv tp_ec_point;
  begin
    l_rv.x := p_point.x;
    l_rv.y := p_point.y;
    l_rv.z := mag( '1' );
    return l_rv;
  end;
  --
  function double_jpoint( p tp_ec_point, c tp_ec_curve )
  return tp_ec_point
  is
    l_ysqr tp_mag;
    l_z4 tp_mag;
    l_s tp_mag;
    l_m tp_mag;
    l_rv tp_ec_point;
    c_mag_4 tp_mag := mag( '4' );
  begin
    if p.y(0) = 0 and p.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
      l_rv.z := c_mag_0;
    else
      l_ysqr := mulmod( p.y, p.y, c.prime );
      l_z4 := powmod( p.z, c_mag_4, c.prime );
      l_s := mulmod( small_nmulmod( p.x, 4, c.prime ), l_ysqr, c.prime );
      l_m := addmod( small_nmulmod( mulmod( p.x, p.x, c.prime )
                                  , 3
                                  , c.prime
                                  )
                   , mulmod( c.a, l_z4, c.prime )
                   , c.prime
                   );
      l_rv.x := submod( mulmod( l_m, l_m, c.prime )
                      , small_nmulmod( l_s, 2, c.prime )
                      , c.prime
                      );
      l_rv.y := submod( mulmod( l_m, submod( l_s, l_rv.x, c.prime ), c.prime )
                      , small_nmulmod( mulmod( l_ysqr, l_ysqr, c.prime ), 8, c.prime )
                      , c.prime
                      );
      l_rv.z := mulmod( small_nmulmod( p.y, 2, c.prime ), p.z, c.prime );
    end if;
    return l_rv;
  end;
  --
  function add_jpoint( p1 tp_ec_point, p2 tp_ec_point, c tp_ec_curve )
  return tp_ec_point
  is
    l_p1z_pwr2 tp_mag;
    l_p2z_pwr2 tp_mag;
    l_u1 tp_mag;
    l_u2 tp_mag;
    l_s1 tp_mag;
    l_s2 tp_mag;
    l_h tp_mag;
    l_h2 tp_mag;
    l_h3 tp_mag;
    l_r tp_mag;
    l_u1h2 tp_mag;
    l_rv tp_ec_point;
  begin
    if p1.y(0) = 0 and p1.y.count = 1
    then -- infinity
      return p2;
    end if;
    if p2.y(0) = 0 and p2.y.count = 1
    then -- infinity
      return p1;
    end if;
    l_p1z_pwr2 := mulmod( p1.z, p1.z, c.prime );
    l_p2z_pwr2 := mulmod( p2.z, p2.z, c.prime );
    l_u1 := mulmod( p1.x, l_p2z_pwr2, c.prime );
    l_u2 := mulmod( p2.x, l_p1z_pwr2, c.prime );
    l_s1 := mulmod( p1.y, mulmod( l_p2z_pwr2, p2.z, c.prime ), c.prime );
    l_s2 := mulmod( p2.y, mulmod( l_p1z_pwr2, p1.z, c.prime ), c.prime );
    if requal( l_u1, l_u2 )
    then
       if requal( l_s1, l_s2 )
       then
         l_rv := double_jpoint( p1, c );
       else
         l_rv.x := c_mag_0; -- infinity
         l_rv.y := c_mag_0;
         l_rv.z := c_mag_0;
       end if;
    else
      l_h := submod( l_u2, l_u1, c.prime );
      l_r := submod( l_s2, l_s1, c.prime );
      l_h2 := mulmod( l_h, l_h, c.prime );
      l_h3 := mulmod( l_h2, l_h, c.prime );
      l_u1h2 := mulmod( l_h2, l_u1, c.prime );
      l_rv.x := submod( submod( mulmod( l_r, l_r, c.prime ), l_h3, c.prime )
                      , small_nmulmod( l_u1h2, 2, c.prime )
                      , c.prime
                      );
      l_rv.y := submod( mulmod( l_r, submod( l_u1h2, l_rv.x, c.prime ), c.prime )
                      , mulmod( l_s1, l_h3, c.prime )
                      , c.prime
                      );
      l_rv.z := mulmod( l_h, mulmod( p1.z, p2.z, c.prime ), c.prime );
    end if;
    return l_rv;
  end;
  --
  function multiply_jpoint( p tp_ec_point, m tp_mag, c tp_ec_curve )
  return tp_ec_point
  is
    l_rv tp_ec_point;
  begin
    if p.y(0) = 0 and p.y.count = 1
    then -- infinity
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_0;
      l_rv.z := c_mag_0;
    elsif m(0) = 1 and m.count = 1
    then
      l_rv := p;
    elsif r_greater_equal( m, c.group_order )
    then
      l_rv := multiply_jpoint( p, xmod( m, c.group_order ), c );
    elsif bitand( m(0), 1 ) = 0
    then
      l_rv := double_jpoint( multiply_jpoint( p, rdiv2( m ), c ), c );
    else
      l_rv := add_jpoint( double_jpoint( multiply_jpoint( p, rdiv2( m ), c ), c ), p, c );
    end if;
    return l_rv;
  end;
  --
  function add_point( pa tp_ec_point, pb tp_ec_point, pc tp_ec_curve )
  return tp_ec_point
  is
  begin
    return from_jacobian( add_jpoint( to_jacobian( pa ), to_jacobian( pb ), pc ), pc );
  end;
  --
  function multiply_point( pa tp_ec_point, pm tp_mag, pc tp_ec_curve )
  return tp_ec_point
  is
  begin
    return from_jacobian( multiply_jpoint( to_jacobian( pa ), pm, pc ), pc );
  end;
  --
  procedure ed_group_element( p_bytes raw, p_curve tp_ed_curve, p_ge out tp_ed_point )
  is
    l_y tp_mag;
    l_yy tp_mag;
    l_u tp_mag;
    l_v tp_mag;
    l_v3 tp_mag;
    l_x tp_mag;
    l_vxx tp_mag;
  begin
    l_y := mag( utl_raw.bit_and( utl_raw.reverse( p_bytes ), '7F' ) );
    l_yy := mulmod( l_y, l_y, p_curve.q );
    l_u := nsub( l_yy, 1 );
    l_v := addmod( mulmod( l_yy, p_curve.d, p_curve.q ), c_mag_1, p_curve.q );
    l_v3 := mulmod( l_v, rmul( l_v, l_v ), p_curve.q );
    l_x := mulmod( rmul( l_u, l_v ), rmul( l_v3, l_v3 ), p_curve.q );
    l_x := powmod( l_x, rdiv2( rdiv2( rdiv2( nsub( p_curve.q, 5 ) ) ) ), p_curve.q );
    l_x := mulmod( l_v3, rmul( l_x, l_u ), p_curve.q );
    l_vxx := mulmod( l_v, rmul( l_x, l_x ), p_curve.q );
    if not requal( l_vxx, l_u )
    then
      if requal( radd( l_vxx, l_u ), p_curve.q )
      then
        l_x := mulmod( l_x, p_curve.i, p_curve.q );
      else
        raise value_error;
      end if;
    end if;
    if bitand( l_x(0), 1 ) != standard.sign( utl_raw.compare( utl_raw.bit_and( utl_raw.substr( p_bytes, -1 ), '80' ), null ) )
    then
      l_x := submod( p_curve.q, l_x, p_curve.q );
    end if;
    p_ge.x := l_x;
    p_ge.y := l_y;
    p_ge.z := c_mag_1;
    p_ge.t := mulmod( l_x, l_y, p_curve.q );
  end;
  --
  function ed_add( p_a tp_ed_point, p_b tp_ed_point, p_curve tp_ed_curve )
  return tp_ed_point
  is
    l_ypx tp_mag;
    l_ymx tp_mag;
    l_a tp_mag;
    l_b tp_mag;
    l_c tp_mag;
    l_d tp_mag;
    l_zz tp_mag;
    l_rv tp_ed_point;
    l_xn tp_mag;
    l_yn tp_mag;
    l_zn tp_mag;
    l_tn tp_mag;
  begin
    l_ypx := addmod( p_a.y, p_a.x, p_curve.q );
    l_ymx := submod( p_a.y, p_a.x, p_curve.q );
    l_a := mulmod( l_ypx, addmod( p_b.y, p_b.x, p_curve.q ), p_curve.q );
    l_b := mulmod( l_ymx, submod( p_b.y, p_b.x, p_curve.q ), p_curve.q );
    l_c := mulmod( p_a.t, rmul( p_b.t, nmul( p_curve.d, 2 ) ), p_curve.q );
    l_zz := mulmod( p_a.z, p_b.z, p_curve.q );
    l_d := addmod( l_zz, l_zz, p_curve.q );
    l_xn := submod( l_a, l_b, p_curve.q );
    l_yn := addmod( l_a, l_b, p_curve.q );
    l_zn := addmod( l_d, l_c, p_curve.q );
    l_tn := submod( l_d, l_c, p_curve.q );
    l_rv.x := mulmod( l_xn, l_tn, p_curve.q );
    l_rv.y := mulmod( l_yn, l_zn, p_curve.q );
    l_rv.z := mulmod( l_zn, l_tn, p_curve.q );
    l_rv.t := mulmod( l_xn, l_yn, p_curve.q );
    return l_rv;
  end;
  --
  function dbl( p_ge tp_ed_point, p_curve tp_ed_curve )
  return tp_ed_point
  is
    l_xx tp_mag;
    l_yy tp_mag;
    l_b tp_mag;
    l_a tp_mag;
    l_aa tp_mag;
    l_rv tp_ed_point;
    l_yn tp_mag;
    l_zn tp_mag;
    l_tn tp_mag;
  begin
    l_xx := mulmod( p_ge.x, p_ge.x, p_curve.q );
    l_yy := mulmod( p_ge.y, p_ge.y, p_curve.q );
    l_b := mulmod( p_ge.z, p_ge.z, p_curve.q );
    l_b := addmod( l_b, l_b, p_curve.q );
    l_a := addmod( p_ge.x, p_ge.y, p_curve.q );
    l_aa := mulmod( l_a, l_a, p_curve.q );
    l_yn := addmod( l_yy, l_xx, p_curve.q );
    l_zn := submod( l_yy, l_xx, p_curve.q );
    l_tn := submod( l_b, l_zn, p_curve.q );
    l_rv.x := mulmod( submod( l_aa, l_yn, p_curve.q ), l_tn, p_curve.q );
    l_rv.y := mulmod( l_yn, l_zn, p_curve.q );
    l_rv.z := mulmod( l_zn, l_tn, p_curve.q );
    l_rv.t := mulmod( submod( l_aa, l_yn, p_curve.q ), l_yn, p_curve.q );
    return l_rv;
  end;
  --
  function ed_scalarmultiply( p_ge tp_ed_point, p_curve tp_ed_curve, p_e tp_mag )
  return tp_ed_point
  is
    l_rv tp_ed_point;
  begin
    if p_e.count = 1 and p_e( 0 ) = 0
    then
      l_rv.x := c_mag_0;
      l_rv.y := c_mag_1;
      l_rv.z := c_mag_1;
      l_rv.t := c_mag_0;
    else
      l_rv := dbl( ed_scalarmultiply( p_ge, p_curve, rdiv2( p_e ) ), p_curve );
      if bitand( p_e( 0 ), 1 ) = 1
      then
        l_rv := ed_add( l_rv, p_ge, p_curve );
      end if;
    end if;
    return l_rv;
  end;
  --
  function ed_point2bytes( p_x tp_ed_point, p_curve tp_ed_curve )
  return varchar2
  is
    l_inv tp_mag;
    l_y tp_mag;
    l_rv varchar2(3999);
  begin
    l_inv := powmod( p_x.z, nsub( p_curve.q, 2 ), p_curve.q );
    l_y := mulmod( p_x.y, l_inv, p_curve.q );
    l_rv := substr( lpad( demag( l_y ), p_curve.nlen * 2, '0' ), - p_curve.nlen * 2 );
    if bitand( mulmod( p_x.x, l_inv, p_curve.q )(0), 1 ) = 1
    then
      l_rv := utl_raw.bit_or( '80', l_rv );
    end if;
    return l_rv;
  end;
  --
  function negate_ed_point( p_ge raw, p_curve tp_ed_curve )
  return tp_ed_point
  is
    l_ge tp_ed_point;
    l_rv tp_ed_point;
  begin
    ed_group_element( p_ge, p_curve, l_ge );
    l_rv.x := submod( c_mag_0, small_nmulmod( l_ge.x, 4, p_curve.q ), p_curve.q );
    l_rv.y := small_nmulmod( l_ge.y, 4, p_curve.q );
    l_rv.z := c_mag_4;
    l_rv.t := submod( c_mag_0, small_nmulmod( mulmod( l_ge.x, l_ge.y, p_curve.q ), 4, p_curve.q ), p_curve.q );
    return l_rv;
  end;
  --
  function strip_header_and_footer( p_key raw )
  return raw
  is
    l_key varchar2(32767);
  begin
    l_key := utl_raw.cast_to_varchar2( p_key );
    l_key := rtrim( ltrim( l_key, ' ' || chr(10) || chr(13) ) , ' ' || chr(10) || chr(13) );
    if substr( l_key, 1, 1 ) = '-'
    then
      l_key := trim( '-' from l_key );
      l_key := ltrim( substr( l_key, instr( l_key, '-' ) ), '-' || chr(10) || chr(13) );
      l_key := rtrim( substr( l_key, 1, instr( l_key, '-', -1 ) ), '-' || chr(10) || chr(13) );
    end if;
    return  utl_raw.cast_to_raw( l_key );
  end;
  --
  function base64_decode( p_key raw )
  return raw
  is
  begin
    return utl_encode.base64_decode( strip_header_and_footer( p_key ) );
  end;
  --
  function get_len( p_key raw, p_ind in out pls_integer )
  return pls_integer
  is
    l_len pls_integer;
    l_tmp pls_integer;
  begin
    p_ind := p_ind + 1;
    l_len := to_number( utl_raw.substr( p_key, p_ind, 1 ), 'xx' );
    if l_len > 127
    then
      l_tmp := l_len - 128;
      p_ind := p_ind + 1;
      l_len := to_number( utl_raw.substr( p_key, p_ind, l_tmp ), rpad( 'x', 2 * l_tmp, 'x' ) );
      p_ind := p_ind + l_tmp;
    else
      p_ind := p_ind + 1;
    end if;
    return l_len;
  end;
  --
  procedure check_starting_sequence( p_key raw, p_ind in out pls_integer )
  is
    l_len pls_integer;
  begin
    p_ind := nvl( p_ind, 1 );
    if utl_raw.substr( p_key, p_ind, 1 ) != c_SEQUENCE
    then
      raise value_error;
    end if;
    l_len := get_len( p_key, p_ind );
  end;
  --
  function get_bytes( p_type raw, p_key raw, p_ind in out pls_integer, p_skip_enclosing_context boolean := true )
  return raw
  is
    l_first raw(1);
    l_len pls_integer;
  begin
    l_first := utl_raw.substr( p_key, p_ind, 1 );
    if l_first != p_type
    then
      if p_skip_enclosing_context and utl_raw.bit_and( l_first, 'C0' ) = '80'
      then
        l_len := get_len( p_key, p_ind );
        return get_bytes( p_type, p_key, p_ind, p_skip_enclosing_context );
      else
        raise value_error;
      end if;
    end if;
    l_len := get_len( p_key, p_ind );
    p_ind := p_ind + l_len;
    if l_len != 0
    then
      return utl_raw.substr( p_key, p_ind - l_len, l_len );
    else
      return null;
    end if;
  end;
  --
  function get_integer( p_key raw, p_ind in out pls_integer )
  return raw
  is
  begin
    return get_bytes( c_INTEGER, p_key, p_ind );
  end;
  --
  function get_octect( p_key raw, p_ind in out pls_integer )
  return raw
  is
  begin
    return get_bytes( c_OCTECT, p_key, p_ind );
  end;
  --
  function get_oid( p_key raw, p_ind in out pls_integer )
  return raw
  is
  begin
    return get_bytes( c_OID, p_key, p_ind );
  end;
  --
  function get_bit_string( p_key raw, p_ind in out pls_integer )
  return raw
  is
  begin
    -- assume always primitive encoding
    -- skip unused bits value, assume always 0
    return utl_raw.substr( get_bytes( c_BIT_STRING, p_key, p_ind ), 2 );
  end;
  --
  function get_null( p_key raw, p_ind in out pls_integer )
  return raw
  is
  begin
    return get_bytes( c_NULL, p_key, p_ind );
  end;
  --
  function parse_DER_RSA_PRIV_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_dummy raw(3999);
    l_ind pls_integer;
    l_len pls_integer;
    l_tmp pls_integer;
  begin
    p_key_parameters.delete;
    check_starting_sequence( p_key, l_ind );
    l_dummy := get_integer( p_key, l_ind );  -- version
    if utl_raw.substr( p_key, l_ind, 1 ) = c_SEQUENCE
    then -- PKCS#8
      l_tmp := l_ind;
      l_len := get_len( p_key, l_ind );
      if get_oid( p_key, l_ind ) != '2A864886F70D010101' -- 1.2.840.113549.1.1.1 rsaEncryption
      then
        raise value_error;
      end if;
      l_ind := l_tmp + l_len + 2; -- skip optional stuff of AlgorithmIdentifier
      if utl_raw.substr( p_key, l_ind, 1 ) = c_OCTECT
      then
        l_len := get_len( p_key, l_ind );
      elsif utl_raw.substr( p_key, l_ind, 1 ) = c_BIT_STRING
      then
        l_len := get_len( p_key, l_ind );
        l_ind := l_ind + 1; -- skip bits unused
      else
        raise value_error;
      end if;
      check_starting_sequence( p_key, l_ind );
      l_dummy := get_integer( p_key, l_ind );  -- version
    end if;
    -- process PKCS#1
    p_key_parameters(1) := get_integer( p_key, l_ind ); -- n modulus
    p_key_parameters(2) := get_integer( p_key, l_ind ); -- e public
    p_key_parameters(3) := get_integer( p_key, l_ind ); -- d private
    p_key_parameters(5) := get_integer( p_key, l_ind ); -- p prime1
    p_key_parameters(6) := get_integer( p_key, l_ind ); -- q prime2
    p_key_parameters(7) := get_integer( p_key, l_ind ); -- d mod (p-1) exponent1
    p_key_parameters(8) := get_integer( p_key, l_ind ); -- d mod (q-1) exponent2
    p_key_parameters(4) := get_integer( p_key, l_ind ); -- (inverse of q) mod p coefficient
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  function parse_DER_RSA_PUB_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_dummy raw(3999);
    l_ind pls_integer;
    l_len pls_integer;
    l_tmp pls_integer;
  begin
    p_key_parameters.delete;
    check_starting_sequence( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) = c_SEQUENCE
    then -- PKCS#8
      l_tmp := l_ind;
      l_len := get_len( p_key, l_ind );
      if get_oid( p_key, l_ind ) != '2A864886F70D010101' -- 1.2.840.113549.1.1.1 rsaEncryption
      then
        raise value_error;
      end if;
      l_ind := l_tmp + l_len + 2; -- skip optional stuff of AlgorithmIdentifier
      if utl_raw.substr( p_key, l_ind, 1 ) = c_OCTECT
      then
        l_len := get_len( p_key, l_ind );
      elsif utl_raw.substr( p_key, l_ind, 1 ) = c_BIT_STRING
      then
        l_len := get_len( p_key, l_ind );
        l_ind := l_ind + 1; -- skip bits unused
      else
        raise value_error;
      end if;
      check_starting_sequence( p_key, l_ind );
    end if;
    -- process PKCS#1
    p_key_parameters(1) := get_integer( p_key, l_ind ); -- n modulus
    p_key_parameters(2) := get_integer( p_key, l_ind ); -- e public
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  function parse_DER_EC_PRIV_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_ind pls_integer;
    l_len pls_integer;
    l_version raw(3999);
    l_oid raw(3999);
  begin
    p_key_parameters.delete;
    check_starting_sequence( p_key, l_ind );
    l_version := get_integer( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) = c_SEQUENCE
    then -- PKCS#8
      l_len := get_len( p_key, l_ind );
      if get_oid( p_key, l_ind ) != '2A8648CE3D0201' -- 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
      then
        raise value_error;
      end if;
      l_oid := get_oid( p_key, l_ind );
      if utl_raw.substr( p_key, l_ind, 1 ) != c_OCTECT
      then
        raise value_error;
      end if;
      l_len := get_len( p_key, l_ind );
      if utl_raw.substr( p_key, l_ind, 1 ) != c_SEQUENCE
      then
        raise value_error;
      end if;
      l_len := get_len( p_key, l_ind );
      if get_integer( p_key, l_ind ) != '01'
      then
        raise value_error;
      end if;
      p_key_parameters(2) := get_octect( p_key, l_ind );
    elsif utl_raw.substr( p_key, l_ind, 1 ) = c_OCTECT
    then -- PKCS#1
      p_key_parameters(2) := get_octect( p_key, l_ind );
      l_oid := get_oid( p_key, l_ind );
    else
      raise value_error;
    end if;
    case l_oid
      when '2A8648CE3D030107' -- 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
        then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp256' );
      when '2B81040022'       -- 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
        then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp384' );
      when '2B81040023'       -- 1.3.132.0.35 secp521r1 (SECG (Certicom) named elliptic curve)
      then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp521' );
    else
      raise value_error;
    end case;
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  function parse_DER_EC_PUB_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_ind pls_integer;
    l_len pls_integer;
  begin
    p_key_parameters.delete;
    -- https://crypto.stackexchange.com/questions/31882/can-i-shorten-the-large-ecdsa-public-key-output-file-from-openssl?rq=1
    check_starting_sequence( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) != c_SEQUENCE
    then
      raise value_error;
    end if;
    l_len := get_len( p_key, l_ind );
    if get_oid( p_key, l_ind ) != '2A8648CE3D0201' -- 1.2.840.10045.2.1 ecPublicKey (ANSI X9.62 public key type)
    then
      raise value_error;
    end if;
    case get_oid( p_key, l_ind )
      when '2A8648CE3D030107' -- 1.2.840.10045.3.1.7 prime256v1 (ANSI X9.62 named elliptic curve)
        then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp256' );
      when '2B81040022'       -- 1.3.132.0.34 secp384r1 (SECG (Certicom) named elliptic curve)
        then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp384' );
      when '2B81040023'       -- 1.3.132.0.35 secp521r1 (SECG (Certicom) named elliptic curve)
        then p_key_parameters(1) := utl_raw.cast_to_raw( 'nistp521' );
      else
        raise value_error;
    end case;
    p_key_parameters(2) := get_bit_string( p_key, l_ind );
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  --
  function parse_DER_EdDSA_priv_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_ind pls_integer;
    l_len pls_integer;
    l_version raw(3999);
    l_oid raw(3999);
  begin
    p_key_parameters.delete;
    check_starting_sequence( p_key, l_ind );
    l_version := get_integer( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) != c_SEQUENCE
    then
      raise value_error;
    end if;
    l_len := get_len( p_key, l_ind );
    l_oid := get_oid( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) != c_OCTECT
    then
      raise value_error;
    end if;
    l_len := get_len( p_key, l_ind );
    if l_oid = '2B6570' -- 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
    then
      p_key_parameters(1) := utl_raw.cast_to_raw( 'ed25519' );
      p_key_parameters(2) := get_octect( p_key, l_ind );
    else
      raise value_error;
    end if;
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  function parse_DER_EdDSA_PUB_key
    ( p_key raw
    , p_key_parameters out tp_key_parameters
    )
  return boolean
  is
    l_ind pls_integer;
    l_len pls_integer;
    l_oid raw(3999);
  begin
    p_key_parameters.delete;
    check_starting_sequence( p_key, l_ind );
    if utl_raw.substr( p_key, l_ind, 1 ) != c_SEQUENCE
    then
      raise value_error;
    end if;
    l_len := get_len( p_key, l_ind );
    l_oid := get_oid( p_key, l_ind );
    if l_oid = '2B6570' -- 1.3.101.112 curveEd25519 (EdDSA 25519 signature algorithm)
    then
      p_key_parameters(1) := utl_raw.cast_to_raw( 'ed25519' );
      p_key_parameters(2) := get_bit_string( p_key, l_ind );
    else
      raise value_error;
    end if;
    return true;
  exception when value_error
    then
      p_key_parameters.delete;
      return false;
  end;
  --
  function mgf1( p_seed raw, p_len pls_integer, p_hash_type pls_integer )
  return raw
  is
    l_rv raw(32767);
  begin
    for i in 0 .. 100
    loop
      l_rv := utl_raw.concat( l_rv, hash( utl_raw.concat( p_seed, to_char( i, 'fm0XXXXXXX' ) ), p_hash_type ) );
      exit when utl_raw.length( l_rv ) >= p_len;
    end loop;
    return utl_raw.substr( l_rv, 1, p_len );
  end;
  --
  function bitor( x number, y number )
  return number
  is
  begin
    return x + y - bitand( x, y );
  end;
--
  function bitxor( x number, y number )
  return number
  is
  begin
    return x + y - 2 * bitand( x, y );
  end;
--
  function shl( x number, b pls_integer )
  return number
  is
  begin
    return x * power( 2, b );
  end;
--
  function shr( x number, b pls_integer )
  return number
  is
  begin
    return trunc( x / power( 2, b ) );
  end;
--
  function bitor32( x integer, y integer )
  return integer
  is
  begin
    return bitand( x + y - bitand( x, y  ), bmax32 );
  end;
--
  function bitxor32( x integer, y  integer  )
  return integer
  is
  begin
    return bitand( x + y - 2 * bitand( x, y ), bmax32 );
  end;
--
  function ror32( x number, b pls_integer )
  return number
  is
    t number;
  begin
    t := bitand( x, bmax32 );
    return bitand( bitor( shr( t, b ), shl( t, 32 - b ) ), bmax32 );
  end;
--
  function rol32( x number, b pls_integer )
  return number
  is
    t number;
  begin
    t := bitand( x, bmax32 );
    return bitand( bitor( shl( t, b ), shr( t, 32 - b ) ), bmax32 );
  end;
--
  function ror64( x number, b pls_integer )
  return number
  is
    t number;
  begin
    t := bitand( x, bmax64 );
    return bitand( bitor( shr( t, b ), shl( t, 64 - b ) ), bmax64 );
  end;
--
  function rol64( x number, b pls_integer )
  return number
  is
    t number;
  begin
    t := bitand( x, bmax64 );
    return bitand( bitor( shl( t, b ), shr( t, 64 - b ) ), bmax64 );
  end;
--
  function ripemd160( p_msg raw )
  return raw
  is
    t_md varchar2(128);
    fmt2 varchar2(10) := 'fm0XXXXXXX';
    t_len pls_integer;
    t_pad_len pls_integer;
    t_pad varchar2(144);
    t_msg_buf varchar2(32766);
    t_idx pls_integer;
    t_chunksize pls_integer := 16320; -- 255 * 64
    t_block varchar2(128);
--
    st tp_crypto;
    sl tp_crypto;
    sr tp_crypto;
--
    procedure ff( a in out number, b number, c in out number, d number, e number, xi pls_integer, r pls_integer )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := bitand( rol32( a + bitxor( bitxor( b, c ), d ) + x, r ) + e, bmax32 );
      c := rol32( c, 10 );
    end;
--
    procedure ll( a in out number, b number, c in out number, d number, e number, xi pls_integer, r pls_integer, h number )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := bitand( rol32( a + bitxor( b, bitor( c, - d - 1 ) ) + x + h, r ) + e, bmax32 );
      c := rol32( c, 10 );
    end;
--
    procedure gg( a in out number, b number, c in out number, d number, e number, xi pls_integer, r pls_integer, h number )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := bitand( rol32( a + bitor( bitand( b, c ), bitand( - b - 1, d ) ) + x + h, r ) + e, bmax32 );
      c := rol32( c, 10 );
    end;
--
    procedure kk( a in out number, b number, c in out number, d number, e number, xi pls_integer, r pls_integer, h number )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := bitand( rol32( a + bitor( bitand( b, d ), bitand( c, - d - 1 ) ) + x + h, r ) + e, bmax32 );
      c := rol32( c, 10 );
    end;
--
    procedure hh( a in out number, b number, c in out number, d number, e number, xi pls_integer, r pls_integer, h number )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := bitand( rol32( a + bitxor( bitor( b, - c - 1 ), d ) + x + h, r ) + e, bmax32 );
      c := rol32( c, 10 );
    end;
--
    procedure fa( ar in out tp_crypto, s pls_integer, xis tp_crypto, r_cnt tp_crypto )
    is
    begin
      for i in 1 .. 16
      loop
        ff( ar(mod(15-i+s,5)+1),ar(mod(16-i+s,5)+1),ar(mod(17-i+s,5)+1),ar(mod(18-i+s,5)+1),ar(mod(19-i+s,5)+1),xis(i),r_cnt(i) );
      end loop;
    end;
    procedure ga( ar in out tp_crypto, s pls_integer, h number, xis tp_crypto, r_cnt tp_crypto )
    is
    begin
      for i in 1 .. 16
      loop
        gg( ar(mod(15-i+s,5)+1),ar(mod(16-i+s,5)+1),ar(mod(17-i+s,5)+1),ar(mod(18-i+s,5)+1),ar(mod(19-i+s,5)+1),xis(i),r_cnt(i), h );
      end loop;
    end;
    procedure ha( ar in out tp_crypto, s pls_integer, h number, xis tp_crypto, r_cnt tp_crypto )
    is
    begin
      for i in 1 .. 16
      loop
        hh( ar(mod(15-i+s,5)+1),ar(mod(16-i+s,5)+1),ar(mod(17-i+s,5)+1),ar(mod(18-i+s,5)+1),ar(mod(19-i+s,5)+1),xis(i),r_cnt(i), h );
      end loop;
    end;
    procedure ka( ar in out tp_crypto, s pls_integer, h number, xis tp_crypto, r_cnt tp_crypto )
    is
    begin
      for i in 1 .. 16
      loop
        kk( ar(mod(15-i+s,5)+1),ar(mod(16-i+s,5)+1),ar(mod(17-i+s,5)+1),ar(mod(18-i+s,5)+1),ar(mod(19-i+s,5)+1),xis(i),r_cnt(i), h );
      end loop;
    end;
    procedure la( ar in out tp_crypto, s pls_integer, h number, xis tp_crypto, r_cnt tp_crypto )
    is
    begin
      for i in 1 .. 16
      loop
        ll( ar(mod(15-i+s,5)+1),ar(mod(16-i+s,5)+1),ar(mod(17-i+s,5)+1),ar(mod(18-i+s,5)+1),ar(mod(19-i+s,5)+1),xis(i),r_cnt(i), h );
      end loop;
    end;
  begin
    t_len := nvl( utl_raw.length( p_msg ), 0 );
    t_pad_len := 64 - mod( t_len, 64 );
    if t_pad_len < 9
    then
      t_pad_len := 64 + t_pad_len;
    end if;
    t_pad := rpad( '8', t_pad_len * 2 - 16, '0' )
       || utl_raw.cast_from_binary_integer( t_len * 8, utl_raw.little_endian )
       || '00000000';
--
    st := tp_crypto( 1732584193 -- 67452301
                   , 4023233417 -- efcdab89
                   , 2562383102 -- 98badcfe
                   ,  271733878 -- 10325476
                   , 3285377520 -- c3d2e1f0
                   );
--
    sl := tp_crypto( 0, 0, 0, 0, 0 );
    sr := tp_crypto( 0, 0, 0, 0, 0 );
--
    t_idx := 1;
    while t_idx <= t_len + t_pad_len
    loop
      if t_len - t_idx + 1 >= t_chunksize
      then
        t_msg_buf := utl_raw.substr( p_msg, t_idx, t_chunksize );
        t_idx := t_idx + t_chunksize;
      else
        if t_idx <= t_len
        then
          t_msg_buf := utl_raw.substr( p_msg, t_idx );
          t_idx := t_len + 1;
        else
          t_msg_buf := '';
        end if;
        if nvl( length( t_msg_buf ), 0 ) + t_pad_len * 2 <= 32766
        then
          t_msg_buf := t_msg_buf || t_pad;
          t_idx := t_idx + t_pad_len;
        end if;
      end if;
      for i in 1 .. length( t_msg_buf ) / 128
      loop
        t_block := substr( t_msg_buf, i * 128 - 127, 128 );
--
        for i in 1 .. 5
        loop
         sl(i) := st(i);
         sr(i) := st(i);
        end loop;
--
        fa( sl, 1
          , tp_crypto( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 )
          , tp_crypto(11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8 )
          );
        ga( sl, 5, 1518500249 -- 5a827999
          , tp_crypto( 7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8 )
          , tp_crypto( 7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12 )
          );
        ha( sl, 4, 1859775393  -- 6ed9eba1
          , tp_crypto( 3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12 )
          , tp_crypto(11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5 )
          );
        ka( sl, 3, 2400959708  -- 8f1bbcdc
          , tp_crypto( 1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2 )
          , tp_crypto(11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12 )
          );
        la( sl, 2, 2840853838  -- a953fd4e
          , tp_crypto( 4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13 )
          , tp_crypto( 9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6 )
          );
--
        la( sr, 1, 1352829926  -- 50a28be6
          , tp_crypto( 5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12 )
          , tp_crypto( 8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6 )
          );
        ka( sr, 5, 1548603684  -- 5c4dd124
          , tp_crypto( 6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2 )
          , tp_crypto( 9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11 )
          );
        ha( sr, 4, 1836072691  -- 6d703ef3
          , tp_crypto(15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13 )
          , tp_crypto( 9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5 )
          );
        ga( sr, 3, 2053994217  -- 7a6d76e9
          , tp_crypto( 8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14 )
          , tp_crypto(15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8 )
          );
        fa( sr, 2
          , tp_crypto(12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11 )
          , tp_crypto( 8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11 )
          );
--
        sl(2) := bitand( sl(2) + st(1) + sr(3), bmax32 );
        st(1) := bitand( st(2) + sl(3) + sr(4), bmax32 );
        st(2) := bitand( st(3) + sl(4) + sr(5), bmax32 );
        st(3) := bitand( st(4) + sl(5) + sr(1), bmax32 );
        st(4) := bitand( st(5) + sl(1) + sr(2), bmax32 );
        st(5) := sl(2);
--
      end loop;
    end loop;
--
    t_md := utl_raw.reverse( to_char( st(1), fmt2 ) )
         || utl_raw.reverse( to_char( st(2), fmt2 ) )
         || utl_raw.reverse( to_char( st(3), fmt2 ) )
         || utl_raw.reverse( to_char( st(4), fmt2 ) )
         || utl_raw.reverse( to_char( st(5), fmt2 ) );
--
    return t_md;
  end;
--
  function md2( p_msg raw )
  return raw
  is
    m number;
    b varchar2(32);
    L number := 0;
    type tp_md2 is table of pls_integer index by pls_integer;
    C tp_md2;
    S tp_md2;
    X tp_md2;
    Si varchar2(512) :=
       '292E43C9A2D87C013D3654A1ECF0061362A705F3C0C7738C98932BD9BC4C82CA'
    || '1E9B573CFDD4E01667426F188A17E512BE4EC4D6DA9EDE49A0FBF58EBB2FEE7A'
    || 'A968799115B2073F94C210890B225F21807F5D9A5A903227353ECCE7BFF79703'
    || 'FF1930B348A5B5D1D75E922AAC56AAC64FB838D296A47DB676FC6BE29C7404F1'
    || '459D705964718720865BCF65E62DA8021B6025ADAEB0B9F61C46616934407E0F'
    || '5547A323DD51AF3AC35CF9CEBAC5EA262C530D6E85288409D3DFCDF441814D52'
    || '6ADC37C86CC1ABFA24E17B080CBDB14A7888958BE363E86DE9CBD5FE3B001D39'
    || 'F2EFB70E6658D0E4A67772F8EB754B0A314450B48FED1F1ADB998D339F118314';
--
    procedure checksum( p_b varchar2 )
    is
      t number;
    begin
      for i in 0 .. 15
      loop
        t := to_number( substr( p_b, i * 2 + 1, 2 ), 'xx' );
        C(i) := bitxor( C(i), S( bitand( bitxor( t, L ), 255 ) ) );
        L := C(i);
      end loop;
    end;
--
    procedure process_block( p_b varchar2 )
    is
      t number;
    begin
      for i in 0 .. 15
      loop
        t := to_number( substr( p_b, i * 2 + 1, 2 ), 'xx' );
        X( i + 16 ) := t;
        X( i + 32 ) := bitand( bitxor( t, X(i) ), 255 );
      end loop;
      t := 0;
      for j in 0 .. 17
      loop
        for k in 0 .. 47
        loop
          X(k) := bitxor( X(k), S(t) );
          t := bitand( X(k), 255 );
        end loop;
        t := bitand( t + j, 255 );
      end loop;
    end;
  begin
    for i in 0 .. 15
    loop
      C(i) := 0;
      X(i) := 0;
    end loop;
    for i in 0 .. 255
    loop
       S(i) := to_number( substr( Si, i * 2 + 1, 2 ), 'xx' );
    end loop;
--
    for i in 0 .. nvl( trunc( ( utl_raw.length( p_msg ) ) / 16 ), 0 ) - 1
    loop
      b := utl_raw.substr( p_msg, i * 16 + 1, 16 );
      checksum( b );
      process_block( b );
    end loop;
    m := nvl( mod( utl_raw.length( p_msg ), 16 ), 0 );
    if m = 0
    then
      b := '';
    else
      b := utl_raw.substr( p_msg, -m );
    end if;
    for i in 1 .. 16 - m
    loop
      b := b || to_char( 16 - m, 'fm0X' );
    end loop;
    checksum( b );
    process_block( b );
    b := '';
    for i in 0 .. 15
    loop
      b := b || to_char( C(i), 'fm0X' );
    end loop;
    process_block( b );
    b := '';
    for i in 0 .. 15
    loop
      b := b || to_char( X(i), 'fm0X' );
    end loop;
    return b;
  end;
--
  function md4( p_msg raw )
  return raw
  is
    t_md varchar2(128);
    fmt1 varchar2(10) := 'XXXXXXXX';
    fmt2 varchar2(10) := 'fm0XXXXXXX';
    t_len pls_integer;
    t_pad_len pls_integer;
    t_pad varchar2(144);
    t_msg_buf varchar2(32766);
    t_idx pls_integer;
    t_chunksize pls_integer := 16320; -- 255 * 64
    t_block varchar2(128);
    a number;
    b number;
    c number;
    d number;
    AA number;
    BB number;
    CC number;
    DD number;
--
    procedure ff( a in out number, b number, c number, d number, xi number, s pls_integer )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := a + bitor( bitand( b, c ), bitand( - b - 1, d ) ) + x;
      a := rol32( a, s );
    end;
--
    procedure gg( a in out number, b number, c number, d number, xi number, s pls_integer )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := a + bitor( bitor( bitand( b, c ), bitand( b, d ) ), bitand( c, d ) ) + x + 1518500249; -- to_number( '5a827999', 'xxxxxxxx' );
      a := rol32( a, s );
    end;
--
    procedure hh( a in out number, b number, c number, d number, xi number, s pls_integer )
    is
      x number := utl_raw.cast_to_binary_integer( substr( t_block, xi * 8 + 1, 8 ), utl_raw.little_endian );
    begin
      a := a + bitxor( bitxor( b, c ), d ) + x + 1859775393; -- to_number( '6ed9eba1', 'xxxxxxxx' );
      a := rol32( a, s );
    end;
--
  begin
    t_len := nvl( utl_raw.length( p_msg ), 0 );
    t_pad_len := 64 - mod( t_len, 64 );
    if t_pad_len < 9
    then
      t_pad_len := 64 + t_pad_len;
    end if;
    t_pad := rpad( '8', t_pad_len * 2 - 16, '0' )
       || utl_raw.cast_from_binary_integer( t_len * 8, utl_raw.little_endian )
       || '00000000';
--
    AA := to_number( '67452301', fmt1 );
    BB := to_number( 'efcdab89', fmt1 );
    CC := to_number( '98badcfe', fmt1 );
    DD := to_number( '10325476', fmt1 );
--
    t_idx := 1;
    while t_idx <= t_len + t_pad_len
    loop
      if t_len - t_idx + 1 >= t_chunksize
      then
        t_msg_buf := utl_raw.substr( p_msg, t_idx, t_chunksize );
        t_idx := t_idx + t_chunksize;
      else
        if t_idx <= t_len
        then
          t_msg_buf := utl_raw.substr( p_msg, t_idx );
          t_idx := t_len + 1;
        else
          t_msg_buf := '';
        end if;
        if nvl( length( t_msg_buf ), 0 ) + t_pad_len * 2 <= 32766
        then
          t_msg_buf := t_msg_buf || t_pad;
          t_idx := t_idx + t_pad_len;
        end if;
      end if;
      for i in 1 .. length( t_msg_buf ) / 128
      loop
        t_block := substr( t_msg_buf, i * 128 - 127, 128 );
        a := AA;
        b := BB;
        c := CC;
        d := DD;
--
        for j in 0 .. 3
        loop
          ff( a, b, c, d, j * 4 + 0, 3 );
          ff( d, a, b, c, j * 4 + 1, 7 );
          ff( c, d, a, b, j * 4 + 2, 11 );
          ff( b, c, d, a, j * 4 + 3, 19 );
        end loop;
--
        for j in 0 .. 3
        loop
          gg( a, b, c, d, j + 0, 3 );
          gg( d, a, b, c, j + 4, 5 );
          gg( c, d, a, b, j + 8, 9 );
          gg( b, c, d, a, j + 12, 13 );
        end loop;
--
        for j in 0 .. 3
        loop
          hh( a, b, c, d, bitand( j, 1 ) * 2 + bitand( j, 2 ) / 2 + 0, 3 );
          hh( d, a, b, c, bitand( j, 1 ) * 2 + bitand( j, 2 ) / 2 + 8, 9 );
          hh( c, d, a, b, bitand( j, 1 ) * 2 + bitand( j, 2 ) / 2 + 4, 11 );
          hh( b, c, d, a, bitand( j, 1 ) * 2 + bitand( j, 2 ) / 2 + 12, 15 );
        end loop;
--
        AA := bitand( AA + a, bmax32 );
        BB := bitand( BB + b, bmax32 );
        CC := bitand( CC + c, bmax32 );
        DD := bitand( DD + d, bmax32 );
      end loop;
    end loop;
--
    t_md := utl_raw.reverse( to_char( AA, fmt2 ) )
         || utl_raw.reverse( to_char( BB, fmt2 ) )
         || utl_raw.reverse( to_char( CC, fmt2 ) )
         || utl_raw.reverse( to_char( DD, fmt2 ) );
--
    return t_md;
  end;
--
  function md5( p_msg raw )
  return raw
  is
    t_md varchar2(128);
    fmt1 varchar2(10) := 'XXXXXXXX';
    fmt2 varchar2(10) := 'fm0XXXXXXX';
    t_len pls_integer;
    t_pad_len pls_integer;
    t_pad varchar2(144);
    t_msg_buf varchar2(32766);
    t_idx pls_integer;
    t_chunksize pls_integer := 16320; -- 255 * 64
    t_block varchar2(128);
    type tp_tab is table of number;
    Ht tp_tab;
    K tp_tab;
    s tp_tab;
    H_str varchar2(64);
    K_str varchar2(512);
    a number;
    b number;
    c number;
    d number;
    e number;
    f number;
    g number;
    h number;
  begin
    t_len := nvl( utl_raw.length( p_msg ), 0 );
    t_pad_len := 64 - mod( t_len, 64 );
    if t_pad_len < 9
    then
      t_pad_len := 64 + t_pad_len;
    end if;
    t_pad := rpad( '8', t_pad_len * 2 - 16, '0' )
       || utl_raw.cast_from_binary_integer( t_len * 8, utl_raw.little_endian )
       || '00000000';
--
    s := tp_tab( 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22
               , 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20
               , 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23
               , 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
               );
--
    H_str := '67452301efcdab8998badcfe10325476';
    Ht := tp_tab();
    Ht.extend(4);
    for i in 1 .. 4
    loop
      Ht(i) := to_number( substr( H_str, i * 8 - 7, 8 ), fmt1 );
    end loop;
--
    K_str := 'd76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501'
          || '698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821'
          || 'f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc8'
          || '21e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8a'
          || 'fffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70'
          || '289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665'
          || 'f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd1'
          || '6fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391';
    K := tp_tab();
    K.extend(64);
    for i in 1 .. 64
    loop
      K(i) := to_number( substr( K_str, i * 8 - 7, 8 ), fmt1 );
    end loop;
    t_idx := 1;
    while t_idx <= t_len + t_pad_len
    loop
      if t_len - t_idx + 1 >= t_chunksize
      then
        t_msg_buf := utl_raw.substr( p_msg, t_idx, t_chunksize );
        t_idx := t_idx + t_chunksize;
      else
        if t_idx <= t_len
        then
          t_msg_buf := utl_raw.substr( p_msg, t_idx );
          t_idx := t_len + 1;
        else
          t_msg_buf := '';
        end if;
        if nvl( length( t_msg_buf ), 0 ) + t_pad_len * 2 <= 32766
        then
          t_msg_buf := t_msg_buf || t_pad;
          t_idx := t_idx + t_pad_len;
        end if;
      end if;
      for i in 1 .. length( t_msg_buf ) / 128
      loop
        t_block := substr( t_msg_buf, i * 128 - 127, 128 );
        a := Ht(1);
        b := Ht(2);
        c := Ht(3);
        d := Ht(4);
        for j in 0 .. 63
        loop
          if j <= 15
          then
            F := bitand( bitxor( D, bitand( B, bitxor( C, D ) ) ), bmax32 );
            g := j;
          elsif j <= 31
          then
            F := bitand( bitxor( C, bitand( D, bitxor( B, C ) ) ), bmax32 );
            g := mod( 5*j + 1, 16 );
          elsif j <= 47
          then
            F := bitand( bitxor( B, bitxor( C, D ) ), bmax32 );
            g := mod( 3*j + 5, 16 );
          else
            F := bitand( bitxor( C, bitor( B, - D  - 1 ) ), bmax32 );
            g := mod( 7*j, 16 );
          end if;
          e := D;
          D := C;
          C := B;
          h := utl_raw.cast_to_binary_integer( substr( t_block, g * 8 + 1, 8 ), utl_raw.little_endian );
          B := bitand( B + rol32( bitand( A + F + k( j + 1 ) + h, bmax32 ), s( j + 1 ) ), bmax32 );
          A := e;
        end loop;
        Ht(1) := bitand( Ht(1) + a, bmax32 );
        Ht(2) := bitand( Ht(2) + b, bmax32 );
        Ht(3) := bitand( Ht(3) + c, bmax32 );
        Ht(4) := bitand( Ht(4) + d, bmax32 );
      end loop;
    end loop;
--
    for i in 1 .. 4
    loop
      t_md := t_md || utl_raw.reverse( to_char( Ht(i), fmt2 ) );
    end loop;
--
    return t_md;
  end;
--
  function sha1( p_val raw )
  return raw
  is
    t_val raw(32767);
    t_len pls_integer;
    t_padding raw(128);
    type tp_n is table of integer index by pls_integer;
    w tp_n;
    tw tp_n;
    th tp_n;
    c_ffffffff integer := to_number( 'ffffffff', 'xxxxxxxx' );
    c_5A827999 integer := to_number( '5A827999', 'xxxxxxxx' );
    c_6ED9EBA1 integer := to_number( '6ED9EBA1', 'xxxxxxxx' );
    c_8F1BBCDC integer := to_number( '8F1BBCDC', 'xxxxxxxx' );
    c_CA62C1D6 integer := to_number( 'CA62C1D6', 'xxxxxxxx' );
--
    function radd( x integer, y integer )
    return integer
    is
    begin
      return x + y;
    end;
--
  begin
    th(0) := to_number( hextoraw( '67452301' ), 'xxxxxxxx' );
    th(1) := to_number( hextoraw( 'EFCDAB89' ), 'xxxxxxxx' );
    th(2) := to_number( hextoraw( '98BADCFE' ), 'xxxxxxxx' );
    th(3) := to_number( hextoraw( '10325476' ), 'xxxxxxxx' );
    th(4) := to_number( hextoraw( 'C3D2E1F0' ), 'xxxxxxxx' );
--
    t_len := nvl( utl_raw.length( p_val ), 0 );
    if mod( t_len, 64 ) < 55
    then
      t_padding :=  utl_raw.concat( hextoraw( '80' ), utl_raw.copies( hextoraw( '00' ), 55 - mod( t_len, 64 ) ) );
    elsif mod( t_len, 64 ) = 55
    then
      t_padding :=  hextoraw( '80' );
    else
      t_padding :=  utl_raw.concat( hextoraw( '80' ), utl_raw.copies( hextoraw( '00' ), 119 - mod( t_len, 64 ) ) );
    end if;
    t_padding := utl_raw.concat( t_padding
                               , hextoraw( '00000000' )
                               , utl_raw.cast_from_binary_integer( t_len * 8 ) -- only 32 bits number!!
                               );
    t_val := utl_raw.concat( p_val, t_padding );
    for c in 0 .. utl_raw.length( t_val ) / 64 - 1
    loop
      for i in 0 .. 15
      loop
        w(i) := to_number( utl_raw.substr( t_val, c*64 + i*4 + 1, 4 ), 'xxxxxxxx' );
      end loop;
      for i in 16 .. 79
      loop
        w(i) := rol32( bitxor( bitxor( w(i-3), w(i-8) ), bitxor( w(i-14), w(i-16) ) ), 1 );
      end loop;
--
      for i in 0 .. 4
      loop
        tw(i) := th(i);
      end loop;
--
      for i in 0 .. 19
      loop
        tw(4-mod(i,5)) := tw(4-mod(i,5)) + rol32( tw(4-mod(i+4,5)), 5 )
                        + bitor( bitand( tw(4-mod(i+3,5)), tw(4-mod(i+2,5)) )
                               , bitand( c_ffffffff - tw(4-mod(i+3,5)), tw(4-mod(i+1,5)) )
                               )
                        + w(i) + c_5A827999;
        tw(4-mod(i+3,5)) := rol32( tw( 4-mod(i+3,5)), 30 );
      end loop;
      for i in 20 .. 39
      loop
        tw(4-mod(i,5)) := tw(4-mod(i,5)) + rol32( tw(4-mod(i+4,5)), 5 )
                        + bitxor( bitxor( tw(4-mod(i+3,5)), tw(4-mod(i+2,5)) )
                                , tw(4-mod(i+1,5))
                                )
                        + w(i) + c_6ED9EBA1;
        tw(4-mod(i+3,5)) := rol32( tw( 4-mod(i+3,5)), 30 );
      end loop;
      for i in 40 .. 59
      loop
        tw(4-mod(i,5)) := tw(4-mod(i,5)) + rol32( tw(4-mod(i+4,5)), 5 )
                        + bitor( bitand( tw(4-mod(i+3,5)), tw(4-mod(i+2,5)) )
                               , bitor( bitand( tw(4-mod(i+3,5)), tw(4-mod(i+1,5)) )
                                              , bitand( tw(4-mod(i+2,5)), tw(4-mod(i+1,5)) )
                                              )
                               )
                        + w(i) + c_8F1BBCDC;
        tw(4-mod(i+3,5)) := rol32( tw( 4-mod(i+3,5)), 30 );
      end loop;
      for i in 60 .. 79
      loop
        tw(4-mod(i,5)) := tw(4-mod(i,5)) + rol32( tw(4-mod(i+4,5)), 5 )
                        + bitxor( bitxor( tw(4-mod(i+3,5)), tw(4-mod(i+2,5)) )
                                , tw(4-mod(i+1,5))
                                )
                        + w(i) + c_CA62C1D6;
        tw(4-mod(i+3,5)) := rol32( tw( 4-mod(i+3,5)), 30 );
      end loop;
--
      for i in 0 .. 4
      loop
        th(i) := bitand( th(i) + tw(i), bmax32 );
      end loop;
--
    end loop;
--
    return utl_raw.concat( to_char( th(0), 'fm0000000X' )
                         , to_char( th(1), 'fm0000000X' )
                         , to_char( th(2), 'fm0000000X' )
                         , to_char( th(3), 'fm0000000X' )
                         , to_char( th(4), 'fm0000000X' )
                         );
  end;
--
  function sha256( p_msg raw, p_256 boolean )
  return raw
  is
    t_md varchar2(128);
    fmt1 varchar2(10) := 'xxxxxxxx';
    fmt2 varchar2(10) := 'fm0xxxxxxx';
    t_len pls_integer;
    t_pad_len pls_integer;
    t_pad varchar2(144);
    t_msg_buf varchar2(32766);
    t_idx pls_integer;
    t_chunksize pls_integer := 16320; -- 255 * 64
    t_block varchar2(128);
    type tp_tab is table of number;
    Ht tp_tab;
    K tp_tab;
    w tp_tab;
    H_str varchar2(64);
    K_str varchar2(512);
    a number;
    b number;
    c number;
    d number;
    e number;
    f number;
    g number;
    h number;
    s0 number;
    s1 number;
    maj number;
    ch number;
    t1 number;
    t2 number;
    tmp number;
  begin
    t_len := nvl( utl_raw.length( p_msg ), 0 );
    t_pad_len := 64 - mod( t_len, 64 );
    if t_pad_len < 9
    then
      t_pad_len := 64 + t_pad_len;
    end if;
    t_pad := rpad( '8', t_pad_len * 2 - 8, '0' ) || to_char( t_len * 8, 'fm0XXXXXXX' );
--
    if p_256
    then
      H_str := '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19';
    else
      H_str := 'c1059ed8367cd5073070dd17f70e5939ffc00b316858151164f98fa7befa4fa4';
    end if;
    Ht := tp_tab();
    Ht.extend(8);
    for i in 1 .. 8
    loop
      Ht(i) := to_number( substr( H_str, i * 8 - 7, 8 ), fmt1 );
    end loop;
--
    K_str := '428a2f9871374491b5c0fbcfe9b5dba53956c25b59f111f1923f82a4ab1c5ed5'
          || 'd807aa9812835b01243185be550c7dc372be5d7480deb1fe9bdc06a7c19bf174'
          || 'e49b69c1efbe47860fc19dc6240ca1cc2de92c6f4a7484aa5cb0a9dc76f988da'
          || '983e5152a831c66db00327c8bf597fc7c6e00bf3d5a7914706ca635114292967'
          || '27b70a852e1b21384d2c6dfc53380d13650a7354766a0abb81c2c92e92722c85'
          || 'a2bfe8a1a81a664bc24b8b70c76c51a3d192e819d6990624f40e3585106aa070'
          || '19a4c1161e376c082748774c34b0bcb5391c0cb34ed8aa4a5b9cca4f682e6ff3'
          || '748f82ee78a5636f84c878148cc7020890befffaa4506cebbef9a3f7c67178f2';
    K := tp_tab();
    K.extend(64);
    for i in 1 .. 64
    loop
      K(i) := to_number( substr( K_str, i * 8 - 7, 8 ), fmt1 );
    end loop;
--
    t_idx := 1;
    while t_idx <= t_len + t_pad_len
    loop
      if t_len - t_idx + 1 >= t_chunksize
      then
        t_msg_buf := utl_raw.substr( p_msg, t_idx, t_chunksize );
        t_idx := t_idx + t_chunksize;
      else
        if t_idx <= t_len
        then
          t_msg_buf := utl_raw.substr( p_msg, t_idx );
          t_idx := t_len + 1;
        else
          t_msg_buf := '';
        end if;
        if nvl( length( t_msg_buf ), 0 ) + t_pad_len * 2 <= 32766
        then
          t_msg_buf := t_msg_buf || t_pad;
          t_idx := t_idx + t_pad_len;
        end if;
      end if;
--
      for i in 1 .. length( t_msg_buf ) / 128
      loop
--
        a := Ht(1);
        b := Ht(2);
        c := Ht(3);
        d := Ht(4);
        e := Ht(5);
        f := Ht(6);
        g := Ht(7);
        h := Ht(8);
--
        t_block := substr( t_msg_buf, i * 128 - 127, 128 );
        w := tp_tab();
        w.extend( 64 );
        for j in 1 .. 16
        loop
          w(j) := to_number( substr( t_block, j * 8  - 7, 8 ), fmt1 );
        end loop;
--
        for j in 17 .. 64
        loop
          tmp := w(j-15);
          s0 := bitxor( bitxor( ror32( tmp, 7), ror32( tmp, 18 ) ), shr( tmp, 3 ) );
          tmp := w(j-2);
          s1 := bitxor( bitxor( ror32( tmp, 17), ror32( tmp, 19 ) ), shr( tmp, 10 ) );
          w(j) := bitand( w(j-16) + s0 + w(j-7) + s1, bmax32 );
        end loop;
--
        for j in 1 .. 64
        loop
          s0 := bitxor( bitxor( ror32( a, 2 ), ror32( a, 13 ) ), ror32( a, 22 ) );
          maj := bitxor( bitxor( bitand( a, b ), bitand( a, c ) ), bitand( b, c ) );
          t2 := bitand( s0 + maj, bmax32 );
          s1 := bitxor( bitxor( ror32( e, 6 ), ror32( e, 11 ) ), ror32( e, 25 ) );
          ch := bitxor( bitand( e, f ), bitand( - e - 1, g ) );
          t1 := h + s1 + ch + K(j) + w(j);
          h := g;
          g := f;
          f := e;
          e := d + t1;
          d := c;
          c := b;
          b := a;
          a := t1 + t2;
        end loop;
--
        Ht(1) := bitand( Ht(1) + a, bmax32 );
        Ht(2) := bitand( Ht(2) + b, bmax32 );
        Ht(3) := bitand( Ht(3) + c, bmax32 );
        Ht(4) := bitand( Ht(4) + d, bmax32 );
        Ht(5) := bitand( Ht(5) + e, bmax32 );
        Ht(6) := bitand( Ht(6) + f, bmax32 );
        Ht(7) := bitand( Ht(7) + g, bmax32 );
        Ht(8) := bitand( Ht(8) + h, bmax32 );
--
      end loop;
    end loop;
    for i in 1 .. case when p_256 then 8 else 7 end
    loop
      t_md := t_md || to_char( Ht(i), fmt2 );
    end loop;
    return t_md;
  end;
--
  function sha512( p_msg raw, p_h_str varchar2 )
  return raw
  is
    t_md varchar2(128);
    fmt1 varchar2(20) := 'xxxxxxxxxxxxxxxx';
    fmt2 varchar2(20) := 'fm0xxxxxxxxxxxxxxx';
    t_len pls_integer;
    t_pad_len pls_integer;
    t_pad varchar2(288);
    t_msg_buf varchar2(32766);
    t_idx pls_integer;
    t_chunksize pls_integer := 16256; -- 127 * 128
    t_block varchar2(256);
    type tp_tab is table of number;
    Ht tp_tab;
    K tp_tab;
    w tp_tab;
    K_str varchar2(1280);
    a number;
    b number;
    c number;
    d number;
    e number;
    f number;
    g number;
    h number;
    s0 number;
    s1 number;
    maj number;
    ch number;
    t1 number;
    t2 number;
    tmp number;
  begin
    t_len := nvl( utl_raw.length( p_msg ), 0 );
    t_pad_len := 128 - mod( t_len, 128 );
    if t_pad_len < 17
    then
      t_pad_len := 128 + t_pad_len;
    end if;
    t_pad := rpad( '8', t_pad_len * 2 - 16, '0' ) || to_char( t_len * 8, 'fm0XXXXXXX' );
    Ht := tp_tab();
    Ht.extend(8);
    for i in 1 .. 8
    loop
      Ht(i) := to_number( substr( p_h_str, i * 16 - 15, 16 ), fmt1 );
    end loop;
--
    K_str := '428a2f98d728ae227137449123ef65cdb5c0fbcfec4d3b2fe9b5dba58189dbbc'
          || '3956c25bf348b53859f111f1b605d019923f82a4af194f9bab1c5ed5da6d8118'
          || 'd807aa98a303024212835b0145706fbe243185be4ee4b28c550c7dc3d5ffb4e2'
          || '72be5d74f27b896f80deb1fe3b1696b19bdc06a725c71235c19bf174cf692694'
          || 'e49b69c19ef14ad2efbe4786384f25e30fc19dc68b8cd5b5240ca1cc77ac9c65'
          || '2de92c6f592b02754a7484aa6ea6e4835cb0a9dcbd41fbd476f988da831153b5'
          || '983e5152ee66dfaba831c66d2db43210b00327c898fb213fbf597fc7beef0ee4'
          || 'c6e00bf33da88fc2d5a79147930aa72506ca6351e003826f142929670a0e6e70'
          || '27b70a8546d22ffc2e1b21385c26c9264d2c6dfc5ac42aed53380d139d95b3df'
          || '650a73548baf63de766a0abb3c77b2a881c2c92e47edaee692722c851482353b'
          || 'a2bfe8a14cf10364a81a664bbc423001c24b8b70d0f89791c76c51a30654be30'
          || 'd192e819d6ef5218d69906245565a910f40e35855771202a106aa07032bbd1b8'
          || '19a4c116b8d2d0c81e376c085141ab532748774cdf8eeb9934b0bcb5e19b48a8'
          || '391c0cb3c5c95a634ed8aa4ae3418acb5b9cca4f7763e373682e6ff3d6b2b8a3'
          || '748f82ee5defb2fc78a5636f43172f6084c87814a1f0ab728cc702081a6439ec'
          || '90befffa23631e28a4506cebde82bde9bef9a3f7b2c67915c67178f2e372532b'
          || 'ca273eceea26619cd186b8c721c0c207eada7dd6cde0eb1ef57d4f7fee6ed178'
          || '06f067aa72176fba0a637dc5a2c898a6113f9804bef90dae1b710b35131c471b'
          || '28db77f523047d8432caab7b40c724933c9ebe0a15c9bebc431d67c49c100d4c'
          || '4cc5d4becb3e42b6597f299cfc657e2a5fcb6fab3ad6faec6c44198c4a475817';
    K := tp_tab();
    K.extend(80);
    for i in 1 .. 80
    loop
      K(i) := to_number( substr( K_str, i * 16 - 15, 16 ), fmt1 );
    end loop;
--
    t_idx := 1;
    while t_idx <= t_len + t_pad_len
    loop
      if t_len - t_idx + 1 >= t_chunksize
      then
        t_msg_buf := utl_raw.substr( p_msg, t_idx, t_chunksize );
        t_idx := t_idx + t_chunksize;
      else
        if t_idx <= t_len
        then
          t_msg_buf := utl_raw.substr( p_msg, t_idx );
          t_idx := t_len + 1;
        else
          t_msg_buf := '';
        end if;
        if nvl( length( t_msg_buf ), 0 ) + t_pad_len * 2 <= 32766
        then
          t_msg_buf := t_msg_buf || t_pad;
          t_idx := t_idx + t_pad_len;
        end if;
      end if;
--
      for i in 1 .. length( t_msg_buf ) / 256
      loop
--
        a := Ht(1);
        b := Ht(2);
        c := Ht(3);
        d := Ht(4);
        e := Ht(5);
        f := Ht(6);
        g := Ht(7);
        h := Ht(8);
--
        t_block := substr( t_msg_buf, i * 256 - 255, 256 );
        w := tp_tab();
        w.extend( 80 );
        for j in 1 .. 16
        loop
          w(j) := to_number( substr( t_block, j * 16  - 15, 16 ), fmt1 );
        end loop;
--
        for j in 17 .. 80
        loop
          tmp := w(j-15);
          s0 := bitxor( bitxor( ror64( tmp, 1), ror64( tmp, 8 ) ), shr( tmp, 7 ) );
          tmp := w(j-2);
          s1 := bitxor( bitxor( ror64( tmp, 19), ror64( tmp, 61 ) ), shr( tmp, 6 ) );
          w(j) := bitand( w(j-16) + s0 + w(j-7) + s1, bmax64 );
        end loop;
--
        for j in 1 .. 80
        loop
          s0 := bitxor( bitxor( ror64( a, 28 ), ror64( a, 34 ) ), ror64( a, 39 ) );
          maj := bitxor( bitxor( bitand( a, b ), bitand( a, c ) ), bitand( b, c ) );
          t2 := bitand( s0 + maj, bmax64 );
          s1 := bitxor( bitxor( ror64( e, 14 ), ror64( e, 18 ) ), ror64( e, 41 ) );
          ch := bitxor( bitand( e, f ), bitand( - e - 1, g ) );
          t1 := h + s1 + ch + K(j) + w(j);
          h := g;
          g := f;
          f := e;
          e := d + t1;
          d := c;
          c := b;
          b := a;
          a := t1 + t2;
        end loop;
--
        Ht(1) := bitand( Ht(1) + a, bmax64 );
        Ht(2) := bitand( Ht(2) + b, bmax64 );
        Ht(3) := bitand( Ht(3) + c, bmax64 );
        Ht(4) := bitand( Ht(4) + d, bmax64 );
        Ht(5) := bitand( Ht(5) + e, bmax64 );
        Ht(6) := bitand( Ht(6) + f, bmax64 );
        Ht(7) := bitand( Ht(7) + g, bmax64 );
        Ht(8) := bitand( Ht(8) + h, bmax64 );
--
      end loop;
    end loop;
    for i in 1 .. 8
    loop
      t_md := t_md || to_char( Ht(i), fmt2 );
    end loop;
    return t_md;
  end;
--
  function hash( src raw, typ pls_integer )
  return raw
  is
  begin
    return case typ
             when HASH_MD4 then md4( src )
             when HASH_MD5 then md5( src )
             when HASH_SH1 then sha1( src )
             when HASH_SH224 then sha256( src, false )
             when HASH_SH256 then sha256( src, true )
             when HASH_SH384 then utl_raw.substr( sha512( src
                                                        ,  'cbbb9d5dc1059ed8629a292a367cd5079159015a3070dd17152fecd8f70e5939'
                                                        || '67332667ffc00b318eb44a8768581511db0c2e0d64f98fa747b5481dbefa4fa4'
                                                        )
                                                , 1, 48 )
             when HASH_SH512 then sha512( src
                                        ,  '6a09e667f3bcc908bb67ae8584caa73b3c6ef372fe94f82ba54ff53a5f1d36f1'
                                        || '510e527fade682d19b05688c2b3e6c1f1f83d9abfb41bd6b5be0cd19137e2179'
                                        )
             when HASH_SH512_256 then utl_raw.substr( sha512( src
                                                        ,  '22312194FC2BF72C9F555FA3C84C64C22393B86B6F53B151963877195940EABD'
                                                        || '96283EE2A88EFFE3BE5E1E25538639922B0199FC2C85B8AA0EB72DDC81C52CA2'
                                                        )
                                                , 1, 32 )
             when HASH_SH512_224 then utl_raw.substr( sha512( src
                                                            ,  '8C3D37C819544DA273E1996689DCD4D61DFAB7AE32FF9C82679DD514582F9FCF'
                                                            || '0F6D2B697BD44DA877E36F7304C489423F9D85A86A1D36C81112E6AD91D692A1'
                                                            )
                                                    , 1, 28 )
             when HASH_RIPEMD160 then ripemd160( src )
             when HASH_MD2 then md2( src )
           end;
  end;
--
  function mac( src raw, typ pls_integer, key raw )
  return raw
  is
    t_key raw(128);
    t_len pls_integer;
    t_blocksize pls_integer := case
                                 when typ in ( HMAC_SH384, HMAC_SH512, HMAC_SH512_256, HMAC_SH512_224 )
                                   then 128
                                   else 64
                               end;
    t_typ pls_integer := case typ
                           when HMAC_MD4       then HASH_MD4
                           when HMAC_MD5       then HASH_MD5
                           when HMAC_SH1       then HASH_SH1
                           when HMAC_SH224     then HASH_SH224
                           when HMAC_SH256     then HASH_SH256
                           when HMAC_SH384     then HASH_SH384
                           when HMAC_SH512     then HASH_SH512
                           when HMAC_SH512_256 then HASH_SH512_256
                           when HMAC_SH512_224 then HASH_SH512_224
                           when HMAC_RIPEMD160 then HASH_RIPEMD160
                         end;
  begin
    t_len := utl_raw.length( key );
    if t_len > t_blocksize
    then
      t_key := hash( key, t_typ );
      t_len := utl_raw.length( t_key );
    else
      t_key := key;
    end if;
    if t_len < t_blocksize
    then
      t_key := utl_raw.concat( t_key, utl_raw.copies( hextoraw( '00' ), t_blocksize - t_len ) );
    elsif t_len is null
    then
      t_key := utl_raw.copies( hextoraw( '00' ), t_blocksize );
    end if;
    return hash( utl_raw.concat( utl_raw.bit_xor( utl_raw.copies( hextoraw( '5c' ), t_blocksize ), t_key )
                               , hash( utl_raw.concat( utl_raw.bit_xor( utl_raw.copies( hextoraw( '36' ), t_blocksize ), t_key )
                                                     , src
                                                     )
                                     , t_typ
                                     )
                               )
               , t_typ
               );
  end;
--
  function randombytes( number_bytes positive )
  return raw
  is
    type tp_arcfour_sbox is table of pls_integer index by pls_integer;
    type tp_arcfour is record
      ( s tp_arcfour_sbox
      , i pls_integer
      , j pls_integer
      );
    t_tmp pls_integer;
    t_s2 tp_arcfour_sbox;
    t_arcfour tp_arcfour;
    t_rv varchar2(32767);
    t_seed varchar2(3999);
  begin
    t_seed := utl_raw.cast_from_number( dbms_utility.get_cpu_time )
           || utl_raw.cast_from_number( extract( second from systimestamp ) )
           || utl_raw.cast_from_number( dbms_utility.get_time );
    for i in 0 .. 255
    loop
      t_arcfour.s(i) := i;
    end loop;
    t_seed := t_seed
           || utl_raw.cast_from_number( dbms_utility.get_time )
           || utl_raw.cast_from_number( extract( second from systimestamp ) )
           || utl_raw.cast_from_number( dbms_utility.get_cpu_time );
    for i in 0 .. 255
    loop
      t_s2(i) := to_number( substr( t_seed, mod( i, length( t_seed ) ) + 1, 1 ), 'XX' );
    end loop;
    t_arcfour.j := 0;
    for i in 0 .. 255
    loop
      t_arcfour.j := mod( t_arcfour.j + t_arcfour.s(i) + t_s2(i), 256 );
      t_tmp := t_arcfour.s(i);
      t_arcfour.s(i) := t_arcfour.s( t_arcfour.j );
      t_arcfour.s( t_arcfour.j ) := t_tmp;
    end loop;
    t_arcfour.i := 0;
    t_arcfour.j := 0;
--
    for i in 1 .. 1536
    loop
      t_arcfour.i := bitand( t_arcfour.i + 1, 255 );
      t_arcfour.j := bitand( t_arcfour.j + t_arcfour.s( t_arcfour.i ), 255 );
      t_tmp := t_arcfour.s( t_arcfour.i );
      t_arcfour.s( t_arcfour.i ) := t_arcfour.s( t_arcfour.j );
      t_arcfour.s( t_arcfour.j ) := t_tmp;
    end loop;
--
    for i in 1 .. number_bytes
    loop
      t_arcfour.i := bitand( t_arcfour.i + 1, 255 );
      t_arcfour.j := bitand( t_arcfour.j + t_arcfour.s( t_arcfour.i ), 255 );
      t_tmp := t_arcfour.s( t_arcfour.i );
      t_arcfour.s( t_arcfour.i ) := t_arcfour.s( t_arcfour.j );
      t_arcfour.s( t_arcfour.j ) := t_tmp;
      t_rv := t_rv || to_char( t_arcfour.s( bitand( t_arcfour.s( t_arcfour.i ) + t_arcfour.s( t_arcfour.j ), 255 ) ), 'fm0x' );
    end loop;
    return t_rv;
  end;
--
  procedure aes_encrypt_key
    ( key varchar2
    , p_encrypt_key out nocopy tp_aes_tab
    )
  is
    rcon tp_aes_tab;
    t_r number;
    SS varchar2(512);
    s1 number;
    s2 number;
    s3 number;
    t number;
    Nk pls_integer;
    n pls_integer;
    r pls_integer;
  begin
    SS := '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
       || 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
       || '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
       || 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
       || 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
       || 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
       || 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
       || 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16';
    for i in 0 .. 255
    loop
      s1 := to_number( substr( SS, i * 2 + 1, 2 ), 'XX' );
      s2 := s1 * 2;
      if s2 >= 256
      then
        s2 := bitxor( s2, 283 );
      end if;
      s3 := bitxor( s1, s2 );
      p_encrypt_key(i) := s1;
      t := bitor( bitor( bitor( shl( s2, 24 ), shl( s1, 16 ) ), shl( s1, 8 ) ), s3 );
      p_encrypt_key( 256 + i ) := t;
      t := rol32( t, 24 );
      p_encrypt_key( 512 + i ) := t;
      t := rol32( t, 24 );
      p_encrypt_key( 768 + i ) := t;
      t := rol32( t, 24 );
      p_encrypt_key( 1024 + i ) := t;
    end loop;
--
    t_r := 1;
    rcon(0) := shl( t_r, 24 );
    for i in 1 .. 9
    loop
      t_r := t_r * 2;
      if t_r >= 256
      then
        t_r := bitxor( t_r, 283 );
      end if;
      rcon(i) := shl( t_r, 24 );
    end loop;
    rcon(7) := - rcon(7);
    Nk := length( key ) / 8;
    for i in 0 .. Nk - 1
    loop
      p_encrypt_key( 1280 + i ) := to_number( substr( key, i * 8 + 1, 8 ), 'xxxxxxxx' );
    end loop;
    n := 0;
    r := 0;
    for i in Nk .. Nk * 4 + 27
    loop
      t := p_encrypt_key( 1280 + i - 1 );
      if n = 0
      then
        n := Nk;
        t := bitor( bitor( shl( p_encrypt_key( bitand( shr( t, 16 ), 255 ) ), 24 )
                         , shl( p_encrypt_key( bitand( shr( t, 8  ), 255 ) ), 16 )
                         )
                  , bitor( shl( p_encrypt_key( bitand( t           , 255 ) ), 8 )
                         ,      p_encrypt_key( bitand( shr( t, 24 ), 255 ) )
                         )
                  );
        t := bitxor( t, rcon( r ) );
        r := r + 1;
      elsif ( Nk = 8 and n = 4 )
      then
        t := bitor( bitor( shl( p_encrypt_key( bitand( shr( t, 24 ), 255 ) ), 24 )
                         , shl( p_encrypt_key( bitand( shr( t, 16 ), 255 ) ), 16 )
                         )
                  , bitor( shl( p_encrypt_key( bitand( shr( t, 8  ), 255 ) ), 8 )
                         ,      p_encrypt_key( bitand( t           , 255 ) )
                         )
                  );
      end if;
      n := n -1;
      p_encrypt_key( 1280 + i ) := bitand( bitxor( p_encrypt_key( 1280 + i - Nk ), t ), bmax32 );
    end loop;
  end;
--
  procedure aes_decrypt_key
    ( key varchar2
    , p_decrypt_key out nocopy tp_aes_tab
    )
  is
    Se tp_aes_tab;
    rek tp_aes_tab;
    rcon tp_aes_tab;
    SS varchar2(512);
    s1 number;
    s2 number;
    s3 number;
    i2 number;
    i4 number;
    i8 number;
    i9 number;
    ib number;
    id number;
    ie number;
    t number;
    Nk pls_integer;
    Nw pls_integer;
    n pls_integer;
    r pls_integer;
  begin
    SS := '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
       || 'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
       || '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
       || 'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
       || 'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb'
       || 'e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
       || 'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e'
       || 'e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16';
    for i in 0 .. 255
    loop
      s1 := to_number( substr( SS, i * 2 + 1, 2 ), 'XX' );
      i2 := i * 2;
      if i2 >= 256
      then
        i2 := bitxor( i2, 283 );
      end if;
      i4 := i2 * 2;
      if i4 >= 256
      then
        i4 := bitxor( i4, 283 );
      end if;
      i8 := i4 * 2;
      if i8 >= 256
      then
        i8 := bitxor( i8, 283 );
      end if;
      i9 := bitxor( i8, i );
      ib := bitxor( i9, i2 );
      id := bitxor( i9, i4 );
      ie := bitxor( bitxor( i8, i4 ), i2 );
      Se(i) := s1;
      p_decrypt_key( s1 ) := i;
      t := bitor( bitor( bitor( shl( ie, 24 ), shl( i9, 16 ) ), shl( id, 8 ) ), ib );
      p_decrypt_key( 256 + s1 ) := t;
      t := rol32( t, 24 );
      p_decrypt_key( 512 + s1 ) := t;
      t := rol32( t, 24 );
      p_decrypt_key( 768 + s1 ) := t;
      t := rol32( t, 24 );
      p_decrypt_key( 1024 + s1 ) := t;
    end loop;
--
    t := 1;
    rcon(0) := shl( t, 24 );
    for i in 1 .. 9
    loop
      t := t * 2;
      if t >= 256
      then
        t := bitxor( t, 283 );
      end if;
      rcon(i) := shl( t, 24 );
    end loop;
    rcon(7) := - rcon(7);
    Nk := length( key ) / 8;
    Nw := 4 * ( Nk + 7 );
    for i in 0 .. Nk - 1
    loop
      rek(i) := to_number( substr( key, i * 8 + 1, 8 ), 'xxxxxxxx' );
    end loop;
    n := 0;
    r := 0;
    for i in Nk .. Nw - 1
    loop
      t := rek(i - 1);
      if n = 0
      then
        n := Nk;
        t := bitor( bitor( shl( Se( bitand( shr( t, 16 ), 255 ) ), 24 )
                         , shl( Se( bitand( shr( t, 8  ), 255 ) ), 16 )
                         )
                  , bitor( shl( Se( bitand( t           , 255 ) ), 8 )
                         ,      Se( bitand( shr( t, 24 ), 255 ) )
                         )
                  );
        t := bitxor( t, rcon( r ) );
        r := r + 1;
      elsif ( Nk = 8 and n = 4 )
      then
        t := bitor( bitor( shl( Se( bitand( shr( t, 24 ), 255 ) ), 24 )
                         , shl( Se( bitand( shr( t, 16 ), 255 ) ), 16 )
                         )
                  , bitor( shl( Se( bitand( shr( t, 8  ), 255 ) ), 8 )
                         ,      Se( bitand( t           , 255 ) )
                         )
                  );
      end if;
      n := n -1;
      rek(i) := bitand( bitxor( rek( i - Nk ), t ), bmax32 );
    end loop;
    for i in 0 .. 3
    loop
      p_decrypt_key( 1280 + i ) := rek(Nw - 4 + i);
    end loop;
    for i in 1 .. Nk + 5
    loop
      for j in 0 .. 3
      loop
        t:= rek( Nw - i * 4 - 4 + j );
        t := bitxor( bitxor( p_decrypt_key( 256 + bitand( Se( bitand( shr( t, 24 ), 255 ) ), 255 ) )
                           , p_decrypt_key( 512 + bitand( Se( bitand( shr( t, 16 ), 255 ) ), 255 ) )
                           )
                   , bitxor( p_decrypt_key( 768 + bitand( Se( bitand( shr( t, 8 ), 255 ) ), 255 ) )
                           , p_decrypt_key( 1024 + bitand( Se( bitand( t, 255 ) ), 255 ) )
                           )
                   );
        p_decrypt_key( 1280 + i * 4 + j ) := t;
      end loop;
    end loop;
    for i in Nw - 4 .. Nw - 1
    loop
      p_decrypt_key( 1280 + i ) := rek(i - Nw + 4);
    end loop;
  end;
--
  function aes_encrypt
    ( src varchar2
    , klen pls_integer
    , p_decrypt_key tp_aes_tab
    )
  return raw
  is
    t0 number;
    t1 number;
    t2 number;
    t3 number;
    a0 number;
    a1 number;
    a2 number;
    a3 number;
    k pls_integer := 0;
--
    function grv( a number, b number, c number, d number, v number )
    return varchar2
    is
      t number;
      rv varchar2(256);
    begin
      t := bitxor( p_decrypt_key( bitand( shr( a, 24 ), 255 ) ), shr( v, 24 ) );
      rv := substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( shr( b, 16 ), 255 ) ), shr( v, 16 ) );
      rv := rv || substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( shr( c, 8 ), 255 ) ), shr( v, 8 ) );
      rv := rv || substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( d, 255 ) ), v );
      return rv || substr( to_char( t, '0xxxxxxx' ), -2 );
    end;
  begin
    t0 := bitxor( to_number( substr( src,  1, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1280 ) );
    t1 := bitxor( to_number( substr( src,  9, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1281 ) );
    t2 := bitxor( to_number( substr( src, 17, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1282 ) );
    t3 := bitxor( to_number( substr( src, 25, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1283 ) );
    for i in 1 .. klen / 4 + 5
    loop
      k := k + 4;
      a0 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t0, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t1, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t2, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(    t3     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 )
                  );
      a1 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t1, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t2, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t3, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t0     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 1 )
                  );
      a2 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t2, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t3, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t0, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t1     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 2 )
                  );
      a3 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t3, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t0, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t1, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t2     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 3 )
                  );
      t0 := a0; t1 := a1; t2 := a2; t3 := a3;
    end loop;
    k := k + 4;
    return grv( t0, t1, t2, t3, p_decrypt_key( 1280 + k ) )
        || grv( t1, t2, t3, t0, p_decrypt_key( 1280 + k + 1 ) )
        || grv( t2, t3, t0, t1, p_decrypt_key( 1280 + k + 2 ) )
        || grv( t3, t0, t1, t2, p_decrypt_key( 1280 + k + 3 ) );
  end;
--
  function aes_decrypt
    ( src varchar2
    , klen pls_integer
    , p_decrypt_key tp_aes_tab
    )
  return raw
  is
    t0 number;
    t1 number;
    t2 number;
    t3 number;
    a0 number;
    a1 number;
    a2 number;
    a3 number;
    k pls_integer := 0;
--
    function grv( a number, b number, c number, d number, v number )
    return varchar2
    is
      t number;
      rv varchar2(256);
    begin
      t := bitxor( p_decrypt_key( bitand( shr( a, 24 ), 255 ) ), shr( v, 24 ) );
      rv := substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( shr( b, 16 ), 255 ) ), shr( v, 16 ) );
      rv := rv || substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( shr( c, 8 ), 255 ) ), shr( v, 8 ) );
      rv := rv || substr( to_char( t, '0xxxxxxx' ), -2 );
      t := bitxor( p_decrypt_key( bitand( d, 255 ) ), v );
      return rv || substr( to_char( t, '0xxxxxxx' ), -2 );
    end;
  begin
    t0 := bitxor( to_number( substr( src,  1, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1280 ) );
    t1 := bitxor( to_number( substr( src,  9, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1281 ) );
    t2 := bitxor( to_number( substr( src, 17, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1282 ) );
    t3 := bitxor( to_number( substr( src, 25, 8 ), 'xxxxxxxx' ), p_decrypt_key( 1283 ) );
    for i in 1 .. klen / 4 + 5
    loop
      k := k + 4;
      a0 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t0, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t3, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t2, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t1     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 )
                  );
      a1 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t1, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t0, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t3, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t2     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 1 )
                  );
      a2 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t2, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t1, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t0, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t3     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 2 )
                  );
      a3 := bitxor( bitxor( bitxor( p_decrypt_key( 256 + bitand( shr( t3, 24 ), 255 ) )
                                  , p_decrypt_key( 512 + bitand( shr( t2, 16 ), 255 ) )
                                  )
                          , bitxor( p_decrypt_key( 768 + bitand( shr( t1, 8 ), 255 ) )
                                  , p_decrypt_key( 1024 + bitand(     t0     , 255 ) )
                                  )
                          )
                  , p_decrypt_key( 1280 + i * 4 + 3 )
                  );
      t0 := a0; t1 := a1; t2 := a2; t3 := a3;
    end loop;
    k := k + 4;
    return grv( t0, t3, t2, t1, p_decrypt_key( 1280 + k ) )
        || grv( t1, t0, t3, t2, p_decrypt_key( 1280 + k + 1 ) )
        || grv( t2, t1, t0, t3, p_decrypt_key( 1280 + k + 2 ) )
        || grv( t3, t2, t1, t0, p_decrypt_key( 1280 + k + 3 ) );
  end;
--
  procedure deskey( p_key raw, p_keys out tp_crypto, p_encrypt boolean )
  is
    bytebit tp_crypto := tp_crypto( 128, 64, 32, 16, 8, 4, 2, 1 );
    bigbyte tp_crypto := tp_crypto( to_number( '800000', 'XXXXXX' ), to_number( '400000', 'XXXXXX' ), to_number( '200000', 'XXXXXX' ), to_number( '100000', 'XXXXXX' )
                                  , to_number( '080000', 'XXXXXX' ), to_number( '040000', 'XXXXXX' ), to_number( '020000', 'XXXXXX' ), to_number( '010000', 'XXXXXX' )
                                  , to_number( '008000', 'XXXXXX' ), to_number( '004000', 'XXXXXX' ), to_number( '002000', 'XXXXXX' ), to_number( '001000', 'XXXXXX' )
                                  , to_number( '000800', 'XXXXXX' ), to_number( '000400', 'XXXXXX' ), to_number( '000200', 'XXXXXX' ), to_number( '000100', 'XXXXXX' )
                                  , to_number( '000080', 'XXXXXX' ), to_number( '000040', 'XXXXXX' ), to_number( '000020', 'XXXXXX' ), to_number( '000010', 'XXXXXX' )
                                  , to_number( '000008', 'XXXXXX' ), to_number( '000004', 'XXXXXX' ), to_number( '000002', 'XXXXXX' ), to_number( '000001', 'XXXXXX' )
                                  );
    pcl tp_crypto := tp_crypto( 56, 48, 40, 32, 24, 16,  8
                              ,  0, 57, 49, 41, 33, 25, 17
                              ,  9,  1, 58, 50, 42, 34, 26
                              , 18, 10,  2, 59, 51, 43, 35
                              , 62, 54, 46, 38, 30, 22, 14
                              ,  6, 61, 53, 45, 37, 29, 21
                              , 13,  5, 60, 52, 44, 36, 28
                              , 20, 12,  4, 27, 19, 11, 3
                              );
    pc2 tp_crypto := tp_crypto( 13, 16, 10, 23,  0,  4
                              ,  2, 27, 14,  5, 20,  9
                              , 22, 18, 11, 3 , 25,  7
                              , 15,  6, 26, 19, 12,  1
                              , 40, 51, 30, 36, 46, 54
                              , 29, 39, 50, 44, 32, 47
                              , 43, 48, 38, 55, 33, 52
                              , 45, 41, 49, 35, 28, 31
                              );
    totrot tp_crypto := tp_crypto( 1, 2, 4, 6, 8, 10, 12, 14
                                 , 15, 17, 19, 21, 23, 25, 27, 28
                                 );
    t_key tp_crypto := tp_crypto();
    pclm tp_crypto := tp_crypto();
    pcr tp_crypto := tp_crypto();
    kn tp_crypto := tp_crypto();
    t_l pls_integer;
    t_m pls_integer;
    t_n pls_integer;
    raw0 number;
    raw1 number;
    t_tmp number;
    rawi pls_integer;
    knli pls_integer;
  begin
--
    if SP1 is null
    then
        SP1 := tp_crypto(
        to_number( '01010400', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00010000', 'xxxxxxxx' ), to_number( '01010404', 'xxxxxxxx' ),
        to_number( '01010004', 'xxxxxxxx' ), to_number( '00010404', 'xxxxxxxx' ), to_number( '00000004', 'xxxxxxxx' ), to_number( '00010000', 'xxxxxxxx' ),
        to_number( '00000400', 'xxxxxxxx' ), to_number( '01010400', 'xxxxxxxx' ), to_number( '01010404', 'xxxxxxxx' ), to_number( '00000400', 'xxxxxxxx' ),
        to_number( '01000404', 'xxxxxxxx' ), to_number( '01010004', 'xxxxxxxx' ), to_number( '01000000', 'xxxxxxxx' ), to_number( '00000004', 'xxxxxxxx' ),
        to_number( '00000404', 'xxxxxxxx' ), to_number( '01000400', 'xxxxxxxx' ), to_number( '01000400', 'xxxxxxxx' ), to_number( '00010400', 'xxxxxxxx' ),
        to_number( '00010400', 'xxxxxxxx' ), to_number( '01010000', 'xxxxxxxx' ), to_number( '01010000', 'xxxxxxxx' ), to_number( '01000404', 'xxxxxxxx' ),
        to_number( '00010004', 'xxxxxxxx' ), to_number( '01000004', 'xxxxxxxx' ), to_number( '01000004', 'xxxxxxxx' ), to_number( '00010004', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '00000404', 'xxxxxxxx' ), to_number( '00010404', 'xxxxxxxx' ), to_number( '01000000', 'xxxxxxxx' ),
        to_number( '00010000', 'xxxxxxxx' ), to_number( '01010404', 'xxxxxxxx' ), to_number( '00000004', 'xxxxxxxx' ), to_number( '01010000', 'xxxxxxxx' ),
        to_number( '01010400', 'xxxxxxxx' ), to_number( '01000000', 'xxxxxxxx' ), to_number( '01000000', 'xxxxxxxx' ), to_number( '00000400', 'xxxxxxxx' ),
        to_number( '01010004', 'xxxxxxxx' ), to_number( '00010000', 'xxxxxxxx' ), to_number( '00010400', 'xxxxxxxx' ), to_number( '01000004', 'xxxxxxxx' ),
        to_number( '00000400', 'xxxxxxxx' ), to_number( '00000004', 'xxxxxxxx' ), to_number( '01000404', 'xxxxxxxx' ), to_number( '00010404', 'xxxxxxxx' ),
        to_number( '01010404', 'xxxxxxxx' ), to_number( '00010004', 'xxxxxxxx' ), to_number( '01010000', 'xxxxxxxx' ), to_number( '01000404', 'xxxxxxxx' ),
        to_number( '01000004', 'xxxxxxxx' ), to_number( '00000404', 'xxxxxxxx' ), to_number( '00010404', 'xxxxxxxx' ), to_number( '01010400', 'xxxxxxxx' ),
        to_number( '00000404', 'xxxxxxxx' ), to_number( '01000400', 'xxxxxxxx' ), to_number( '01000400', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '00010004', 'xxxxxxxx' ), to_number( '00010400', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '01010004', 'xxxxxxxx' )
    );
        SP2 := tp_crypto(
        to_number( '80108020', 'xxxxxxxx' ), to_number( '80008000', 'xxxxxxxx' ), to_number( '00008000', 'xxxxxxxx' ), to_number( '00108020', 'xxxxxxxx' ),
        to_number( '00100000', 'xxxxxxxx' ), to_number( '00000020', 'xxxxxxxx' ), to_number( '80100020', 'xxxxxxxx' ), to_number( '80008020', 'xxxxxxxx' ),
        to_number( '80000020', 'xxxxxxxx' ), to_number( '80108020', 'xxxxxxxx' ), to_number( '80108000', 'xxxxxxxx' ), to_number( '80000000', 'xxxxxxxx' ),
        to_number( '80008000', 'xxxxxxxx' ), to_number( '00100000', 'xxxxxxxx' ), to_number( '00000020', 'xxxxxxxx' ), to_number( '80100020', 'xxxxxxxx' ),
        to_number( '00108000', 'xxxxxxxx' ), to_number( '00100020', 'xxxxxxxx' ), to_number( '80008020', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '80000000', 'xxxxxxxx' ), to_number( '00008000', 'xxxxxxxx' ), to_number( '00108020', 'xxxxxxxx' ), to_number( '80100000', 'xxxxxxxx' ),
        to_number( '00100020', 'xxxxxxxx' ), to_number( '80000020', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00108000', 'xxxxxxxx' ),
        to_number( '00008020', 'xxxxxxxx' ), to_number( '80108000', 'xxxxxxxx' ), to_number( '80100000', 'xxxxxxxx' ), to_number( '00008020', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '00108020', 'xxxxxxxx' ), to_number( '80100020', 'xxxxxxxx' ), to_number( '00100000', 'xxxxxxxx' ),
        to_number( '80008020', 'xxxxxxxx' ), to_number( '80100000', 'xxxxxxxx' ), to_number( '80108000', 'xxxxxxxx' ), to_number( '00008000', 'xxxxxxxx' ),
        to_number( '80100000', 'xxxxxxxx' ), to_number( '80008000', 'xxxxxxxx' ), to_number( '00000020', 'xxxxxxxx' ), to_number( '80108020', 'xxxxxxxx' ),
        to_number( '00108020', 'xxxxxxxx' ), to_number( '00000020', 'xxxxxxxx' ), to_number( '00008000', 'xxxxxxxx' ), to_number( '80000000', 'xxxxxxxx' ),
        to_number( '00008020', 'xxxxxxxx' ), to_number( '80108000', 'xxxxxxxx' ), to_number( '00100000', 'xxxxxxxx' ), to_number( '80000020', 'xxxxxxxx' ),
        to_number( '00100020', 'xxxxxxxx' ), to_number( '80008020', 'xxxxxxxx' ), to_number( '80000020', 'xxxxxxxx' ), to_number( '00100020', 'xxxxxxxx' ),
        to_number( '00108000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '80008000', 'xxxxxxxx' ), to_number( '00008020', 'xxxxxxxx' ),
        to_number( '80000000', 'xxxxxxxx' ), to_number( '80100020', 'xxxxxxxx' ), to_number( '80108020', 'xxxxxxxx' ), to_number( '00108000', 'xxxxxxxx' )
    );
        SP3 := tp_crypto(
        to_number( '00000208', 'xxxxxxxx' ), to_number( '08020200', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '08020008', 'xxxxxxxx' ),
        to_number( '08000200', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00020208', 'xxxxxxxx' ), to_number( '08000200', 'xxxxxxxx' ),
        to_number( '00020008', 'xxxxxxxx' ), to_number( '08000008', 'xxxxxxxx' ), to_number( '08000008', 'xxxxxxxx' ), to_number( '00020000', 'xxxxxxxx' ),
        to_number( '08020208', 'xxxxxxxx' ), to_number( '00020008', 'xxxxxxxx' ), to_number( '08020000', 'xxxxxxxx' ), to_number( '00000208', 'xxxxxxxx' ),
        to_number( '08000000', 'xxxxxxxx' ), to_number( '00000008', 'xxxxxxxx' ), to_number( '08020200', 'xxxxxxxx' ), to_number( '00000200', 'xxxxxxxx' ),
        to_number( '00020200', 'xxxxxxxx' ), to_number( '08020000', 'xxxxxxxx' ), to_number( '08020008', 'xxxxxxxx' ), to_number( '00020208', 'xxxxxxxx' ),
        to_number( '08000208', 'xxxxxxxx' ), to_number( '00020200', 'xxxxxxxx' ), to_number( '00020000', 'xxxxxxxx' ), to_number( '08000208', 'xxxxxxxx' ),
        to_number( '00000008', 'xxxxxxxx' ), to_number( '08020208', 'xxxxxxxx' ), to_number( '00000200', 'xxxxxxxx' ), to_number( '08000000', 'xxxxxxxx' ),
        to_number( '08020200', 'xxxxxxxx' ), to_number( '08000000', 'xxxxxxxx' ), to_number( '00020008', 'xxxxxxxx' ), to_number( '00000208', 'xxxxxxxx' ),
        to_number( '00020000', 'xxxxxxxx' ), to_number( '08020200', 'xxxxxxxx' ), to_number( '08000200', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '00000200', 'xxxxxxxx' ), to_number( '00020008', 'xxxxxxxx' ), to_number( '08020208', 'xxxxxxxx' ), to_number( '08000200', 'xxxxxxxx' ),
        to_number( '08000008', 'xxxxxxxx' ), to_number( '00000200', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '08020008', 'xxxxxxxx' ),
        to_number( '08000208', 'xxxxxxxx' ), to_number( '00020000', 'xxxxxxxx' ), to_number( '08000000', 'xxxxxxxx' ), to_number( '08020208', 'xxxxxxxx' ),
        to_number( '00000008', 'xxxxxxxx' ), to_number( '00020208', 'xxxxxxxx' ), to_number( '00020200', 'xxxxxxxx' ), to_number( '08000008', 'xxxxxxxx' ),
        to_number( '08020000', 'xxxxxxxx' ), to_number( '08000208', 'xxxxxxxx' ), to_number( '00000208', 'xxxxxxxx' ), to_number( '08020000', 'xxxxxxxx' ),
        to_number( '00020208', 'xxxxxxxx' ), to_number( '00000008', 'xxxxxxxx' ), to_number( '08020008', 'xxxxxxxx' ), to_number( '00020200', 'xxxxxxxx' )
    );
        SP4 := tp_crypto(
        to_number( '00802001', 'xxxxxxxx' ), to_number( '00002081', 'xxxxxxxx' ), to_number( '00002081', 'xxxxxxxx' ), to_number( '00000080', 'xxxxxxxx' ),
        to_number( '00802080', 'xxxxxxxx' ), to_number( '00800081', 'xxxxxxxx' ), to_number( '00800001', 'xxxxxxxx' ), to_number( '00002001', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '00802000', 'xxxxxxxx' ), to_number( '00802000', 'xxxxxxxx' ), to_number( '00802081', 'xxxxxxxx' ),
        to_number( '00000081', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00800080', 'xxxxxxxx' ), to_number( '00800001', 'xxxxxxxx' ),
        to_number( '00000001', 'xxxxxxxx' ), to_number( '00002000', 'xxxxxxxx' ), to_number( '00800000', 'xxxxxxxx' ), to_number( '00802001', 'xxxxxxxx' ),
        to_number( '00000080', 'xxxxxxxx' ), to_number( '00800000', 'xxxxxxxx' ), to_number( '00002001', 'xxxxxxxx' ), to_number( '00002080', 'xxxxxxxx' ),
        to_number( '00800081', 'xxxxxxxx' ), to_number( '00000001', 'xxxxxxxx' ), to_number( '00002080', 'xxxxxxxx' ), to_number( '00800080', 'xxxxxxxx' ),
        to_number( '00002000', 'xxxxxxxx' ), to_number( '00802080', 'xxxxxxxx' ), to_number( '00802081', 'xxxxxxxx' ), to_number( '00000081', 'xxxxxxxx' ),
        to_number( '00800080', 'xxxxxxxx' ), to_number( '00800001', 'xxxxxxxx' ), to_number( '00802000', 'xxxxxxxx' ), to_number( '00802081', 'xxxxxxxx' ),
        to_number( '00000081', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00802000', 'xxxxxxxx' ),
        to_number( '00002080', 'xxxxxxxx' ), to_number( '00800080', 'xxxxxxxx' ), to_number( '00800081', 'xxxxxxxx' ), to_number( '00000001', 'xxxxxxxx' ),
        to_number( '00802001', 'xxxxxxxx' ), to_number( '00002081', 'xxxxxxxx' ), to_number( '00002081', 'xxxxxxxx' ), to_number( '00000080', 'xxxxxxxx' ),
        to_number( '00802081', 'xxxxxxxx' ), to_number( '00000081', 'xxxxxxxx' ), to_number( '00000001', 'xxxxxxxx' ), to_number( '00002000', 'xxxxxxxx' ),
        to_number( '00800001', 'xxxxxxxx' ), to_number( '00002001', 'xxxxxxxx' ), to_number( '00802080', 'xxxxxxxx' ), to_number( '00800081', 'xxxxxxxx' ),
        to_number( '00002001', 'xxxxxxxx' ), to_number( '00002080', 'xxxxxxxx' ), to_number( '00800000', 'xxxxxxxx' ), to_number( '00802001', 'xxxxxxxx' ),
        to_number( '00000080', 'xxxxxxxx' ), to_number( '00800000', 'xxxxxxxx' ), to_number( '00002000', 'xxxxxxxx' ), to_number( '00802080', 'xxxxxxxx' )
    );
        SP5 := tp_crypto(
        to_number( '00000100', 'xxxxxxxx' ), to_number( '02080100', 'xxxxxxxx' ), to_number( '02080000', 'xxxxxxxx' ), to_number( '42000100', 'xxxxxxxx' ),
        to_number( '00080000', 'xxxxxxxx' ), to_number( '00000100', 'xxxxxxxx' ), to_number( '40000000', 'xxxxxxxx' ), to_number( '02080000', 'xxxxxxxx' ),
        to_number( '40080100', 'xxxxxxxx' ), to_number( '00080000', 'xxxxxxxx' ), to_number( '02000100', 'xxxxxxxx' ), to_number( '40080100', 'xxxxxxxx' ),
        to_number( '42000100', 'xxxxxxxx' ), to_number( '42080000', 'xxxxxxxx' ), to_number( '00080100', 'xxxxxxxx' ), to_number( '40000000', 'xxxxxxxx' ),
        to_number( '02000000', 'xxxxxxxx' ), to_number( '40080000', 'xxxxxxxx' ), to_number( '40080000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '40000100', 'xxxxxxxx' ), to_number( '42080100', 'xxxxxxxx' ), to_number( '42080100', 'xxxxxxxx' ), to_number( '02000100', 'xxxxxxxx' ),
        to_number( '42080000', 'xxxxxxxx' ), to_number( '40000100', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '42000000', 'xxxxxxxx' ),
        to_number( '02080100', 'xxxxxxxx' ), to_number( '02000000', 'xxxxxxxx' ), to_number( '42000000', 'xxxxxxxx' ), to_number( '00080100', 'xxxxxxxx' ),
        to_number( '00080000', 'xxxxxxxx' ), to_number( '42000100', 'xxxxxxxx' ), to_number( '00000100', 'xxxxxxxx' ), to_number( '02000000', 'xxxxxxxx' ),
        to_number( '40000000', 'xxxxxxxx' ), to_number( '02080000', 'xxxxxxxx' ), to_number( '42000100', 'xxxxxxxx' ), to_number( '40080100', 'xxxxxxxx' ),
        to_number( '02000100', 'xxxxxxxx' ), to_number( '40000000', 'xxxxxxxx' ), to_number( '42080000', 'xxxxxxxx' ), to_number( '02080100', 'xxxxxxxx' ),
        to_number( '40080100', 'xxxxxxxx' ), to_number( '00000100', 'xxxxxxxx' ), to_number( '02000000', 'xxxxxxxx' ), to_number( '42080000', 'xxxxxxxx' ),
        to_number( '42080100', 'xxxxxxxx' ), to_number( '00080100', 'xxxxxxxx' ), to_number( '42000000', 'xxxxxxxx' ), to_number( '42080100', 'xxxxxxxx' ),
        to_number( '02080000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '40080000', 'xxxxxxxx' ), to_number( '42000000', 'xxxxxxxx' ),
        to_number( '00080100', 'xxxxxxxx' ), to_number( '02000100', 'xxxxxxxx' ), to_number( '40000100', 'xxxxxxxx' ), to_number( '00080000', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '40080000', 'xxxxxxxx' ), to_number( '02080100', 'xxxxxxxx' ), to_number( '40000100', 'xxxxxxxx' )
    );
        SP6 := tp_crypto(
        to_number( '20000010', 'xxxxxxxx' ), to_number( '20400000', 'xxxxxxxx' ), to_number( '00004000', 'xxxxxxxx' ), to_number( '20404010', 'xxxxxxxx' ),
        to_number( '20400000', 'xxxxxxxx' ), to_number( '00000010', 'xxxxxxxx' ), to_number( '20404010', 'xxxxxxxx' ), to_number( '00400000', 'xxxxxxxx' ),
        to_number( '20004000', 'xxxxxxxx' ), to_number( '00404010', 'xxxxxxxx' ), to_number( '00400000', 'xxxxxxxx' ), to_number( '20000010', 'xxxxxxxx' ),
        to_number( '00400010', 'xxxxxxxx' ), to_number( '20004000', 'xxxxxxxx' ), to_number( '20000000', 'xxxxxxxx' ), to_number( '00004010', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '00400010', 'xxxxxxxx' ), to_number( '20004010', 'xxxxxxxx' ), to_number( '00004000', 'xxxxxxxx' ),
        to_number( '00404000', 'xxxxxxxx' ), to_number( '20004010', 'xxxxxxxx' ), to_number( '00000010', 'xxxxxxxx' ), to_number( '20400010', 'xxxxxxxx' ),
        to_number( '20400010', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00404010', 'xxxxxxxx' ), to_number( '20404000', 'xxxxxxxx' ),
        to_number( '00004010', 'xxxxxxxx' ), to_number( '00404000', 'xxxxxxxx' ), to_number( '20404000', 'xxxxxxxx' ), to_number( '20000000', 'xxxxxxxx' ),
        to_number( '20004000', 'xxxxxxxx' ), to_number( '00000010', 'xxxxxxxx' ), to_number( '20400010', 'xxxxxxxx' ), to_number( '00404000', 'xxxxxxxx' ),
        to_number( '20404010', 'xxxxxxxx' ), to_number( '00400000', 'xxxxxxxx' ), to_number( '00004010', 'xxxxxxxx' ), to_number( '20000010', 'xxxxxxxx' ),
        to_number( '00400000', 'xxxxxxxx' ), to_number( '20004000', 'xxxxxxxx' ), to_number( '20000000', 'xxxxxxxx' ), to_number( '00004010', 'xxxxxxxx' ),
        to_number( '20000010', 'xxxxxxxx' ), to_number( '20404010', 'xxxxxxxx' ), to_number( '00404000', 'xxxxxxxx' ), to_number( '20400000', 'xxxxxxxx' ),
        to_number( '00404010', 'xxxxxxxx' ), to_number( '20404000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '20400010', 'xxxxxxxx' ),
        to_number( '00000010', 'xxxxxxxx' ), to_number( '00004000', 'xxxxxxxx' ), to_number( '20400000', 'xxxxxxxx' ), to_number( '00404010', 'xxxxxxxx' ),
        to_number( '00004000', 'xxxxxxxx' ), to_number( '00400010', 'xxxxxxxx' ), to_number( '20004010', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '20404000', 'xxxxxxxx' ), to_number( '20000000', 'xxxxxxxx' ), to_number( '00400010', 'xxxxxxxx' ), to_number( '20004010', 'xxxxxxxx' )
    );
        SP7 := tp_crypto(
        to_number( '00200000', 'xxxxxxxx' ), to_number( '04200002', 'xxxxxxxx' ), to_number( '04000802', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '00000800', 'xxxxxxxx' ), to_number( '04000802', 'xxxxxxxx' ), to_number( '00200802', 'xxxxxxxx' ), to_number( '04200800', 'xxxxxxxx' ),
        to_number( '04200802', 'xxxxxxxx' ), to_number( '00200000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '04000002', 'xxxxxxxx' ),
        to_number( '00000002', 'xxxxxxxx' ), to_number( '04000000', 'xxxxxxxx' ), to_number( '04200002', 'xxxxxxxx' ), to_number( '00000802', 'xxxxxxxx' ),
        to_number( '04000800', 'xxxxxxxx' ), to_number( '00200802', 'xxxxxxxx' ), to_number( '00200002', 'xxxxxxxx' ), to_number( '04000800', 'xxxxxxxx' ),
        to_number( '04000002', 'xxxxxxxx' ), to_number( '04200000', 'xxxxxxxx' ), to_number( '04200800', 'xxxxxxxx' ), to_number( '00200002', 'xxxxxxxx' ),
        to_number( '04200000', 'xxxxxxxx' ), to_number( '00000800', 'xxxxxxxx' ), to_number( '00000802', 'xxxxxxxx' ), to_number( '04200802', 'xxxxxxxx' ),
        to_number( '00200800', 'xxxxxxxx' ), to_number( '00000002', 'xxxxxxxx' ), to_number( '04000000', 'xxxxxxxx' ), to_number( '00200800', 'xxxxxxxx' ),
        to_number( '04000000', 'xxxxxxxx' ), to_number( '00200800', 'xxxxxxxx' ), to_number( '00200000', 'xxxxxxxx' ), to_number( '04000802', 'xxxxxxxx' ),
        to_number( '04000802', 'xxxxxxxx' ), to_number( '04200002', 'xxxxxxxx' ), to_number( '04200002', 'xxxxxxxx' ), to_number( '00000002', 'xxxxxxxx' ),
        to_number( '00200002', 'xxxxxxxx' ), to_number( '04000000', 'xxxxxxxx' ), to_number( '04000800', 'xxxxxxxx' ), to_number( '00200000', 'xxxxxxxx' ),
        to_number( '04200800', 'xxxxxxxx' ), to_number( '00000802', 'xxxxxxxx' ), to_number( '00200802', 'xxxxxxxx' ), to_number( '04200800', 'xxxxxxxx' ),
        to_number( '00000802', 'xxxxxxxx' ), to_number( '04000002', 'xxxxxxxx' ), to_number( '04200802', 'xxxxxxxx' ), to_number( '04200000', 'xxxxxxxx' ),
        to_number( '00200800', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00000002', 'xxxxxxxx' ), to_number( '04200802', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '00200802', 'xxxxxxxx' ), to_number( '04200000', 'xxxxxxxx' ), to_number( '00000800', 'xxxxxxxx' ),
        to_number( '04000002', 'xxxxxxxx' ), to_number( '04000800', 'xxxxxxxx' ), to_number( '00000800', 'xxxxxxxx' ), to_number( '00200002', 'xxxxxxxx' )
    );
        SP8 := tp_crypto(
        to_number( '10001040', 'xxxxxxxx' ), to_number( '00001000', 'xxxxxxxx' ), to_number( '00040000', 'xxxxxxxx' ), to_number( '10041040', 'xxxxxxxx' ),
        to_number( '10000000', 'xxxxxxxx' ), to_number( '10001040', 'xxxxxxxx' ), to_number( '00000040', 'xxxxxxxx' ), to_number( '10000000', 'xxxxxxxx' ),
        to_number( '00040040', 'xxxxxxxx' ), to_number( '10040000', 'xxxxxxxx' ), to_number( '10041040', 'xxxxxxxx' ), to_number( '00041000', 'xxxxxxxx' ),
        to_number( '10041000', 'xxxxxxxx' ), to_number( '00041040', 'xxxxxxxx' ), to_number( '00001000', 'xxxxxxxx' ), to_number( '00000040', 'xxxxxxxx' ),
        to_number( '10040000', 'xxxxxxxx' ), to_number( '10000040', 'xxxxxxxx' ), to_number( '10001000', 'xxxxxxxx' ), to_number( '00001040', 'xxxxxxxx' ),
        to_number( '00041000', 'xxxxxxxx' ), to_number( '00040040', 'xxxxxxxx' ), to_number( '10040040', 'xxxxxxxx' ), to_number( '10041000', 'xxxxxxxx' ),
        to_number( '00001040', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ), to_number( '10040040', 'xxxxxxxx' ),
        to_number( '10000040', 'xxxxxxxx' ), to_number( '10001000', 'xxxxxxxx' ), to_number( '00041040', 'xxxxxxxx' ), to_number( '00040000', 'xxxxxxxx' ),
        to_number( '00041040', 'xxxxxxxx' ), to_number( '00040000', 'xxxxxxxx' ), to_number( '10041000', 'xxxxxxxx' ), to_number( '00001000', 'xxxxxxxx' ),
        to_number( '00000040', 'xxxxxxxx' ), to_number( '10040040', 'xxxxxxxx' ), to_number( '00001000', 'xxxxxxxx' ), to_number( '00041040', 'xxxxxxxx' ),
        to_number( '10001000', 'xxxxxxxx' ), to_number( '00000040', 'xxxxxxxx' ), to_number( '10000040', 'xxxxxxxx' ), to_number( '10040000', 'xxxxxxxx' ),
        to_number( '10040040', 'xxxxxxxx' ), to_number( '10000000', 'xxxxxxxx' ), to_number( '00040000', 'xxxxxxxx' ), to_number( '10001040', 'xxxxxxxx' ),
        to_number( '00000000', 'xxxxxxxx' ), to_number( '10041040', 'xxxxxxxx' ), to_number( '00040040', 'xxxxxxxx' ), to_number( '10000040', 'xxxxxxxx' ),
        to_number( '10040000', 'xxxxxxxx' ), to_number( '10001000', 'xxxxxxxx' ), to_number( '10001040', 'xxxxxxxx' ), to_number( '00000000', 'xxxxxxxx' ),
        to_number( '10041040', 'xxxxxxxx' ), to_number( '00041000', 'xxxxxxxx' ), to_number( '00041000', 'xxxxxxxx' ), to_number( '00001040', 'xxxxxxxx' ),
        to_number( '00001040', 'xxxxxxxx' ), to_number( '00040040', 'xxxxxxxx' ), to_number( '10000000', 'xxxxxxxx' ), to_number( '10041000', 'xxxxxxxx' )
    );
    end if;
--
    t_key.extend(8);
    for i in 1 .. 8
    loop
      t_key(i) := to_number( utl_raw.substr( p_key, i, 1 ), 'XX' );
    end loop;
    pclm.extend(56);
    for j in 1 .. 56
    loop
      pclm(j) := standard.sign( bitand( t_key( trunc( pcl( j ) / 8 ) + 1 ), bytebit( bitand( pcl( j ), 7 ) + 1 ) ) );
    end loop;
    kn.extend(32);
    pcr.extend(56);
    for i in 0 .. 15
    loop
      t_m := case when p_encrypt then i else 15 - i end * 2;
      t_n := t_m + 1;
      kn(t_m+1) := 0;
      kn(t_n+1) := 0;
      for j in 0 .. 27
      loop
        t_l := j + totrot(i+1);
        if t_l < 28
        then
          pcr(j+1) := pclm( t_l + 1 );
        else
          pcr(j+1) := pclm( t_l - 28 + 1 );
        end if;
      end loop;
      for j in 28 .. 55
      loop
        t_l := j + totrot(i+1);
        if t_l < 56
        then
          pcr(j+1) := pclm( t_l + 1 );
        else
          pcr(j+1) := pclm( t_l - 28 + 1 );
        end if;
      end loop;
      for j in 0 .. 23
      loop
        if pcr( pc2( j + 1 ) + 1 ) != 0
        then
          kn( t_m + 1 ) := bitor32( kn( t_m + 1 ), bigbyte( j + 1 ) );
        end if;
        if pcr( pc2( j + 24 + 1 ) + 1 ) != 0
        then
          kn( t_n + 1 ) := bitor32( kn( t_n + 1 ), bigbyte( j + 1 ) );
        end if;
      end loop;
    end loop;
--
    p_keys := tp_crypto();
    p_keys.extend(32);
    rawi := 1;
    knli := 1;
    for i in 0 .. 15
    loop
      raw0 := kn(rawi);
      rawi := rawi + 1;
      raw1 := kn(rawi);
      rawi := rawi + 1;
      t_tmp := bitand( raw0, to_number( 'fc0000', 'xxxxxx' ) ) * 64;
      t_tmp := bitor32( t_tmp, bitand( raw0, to_number( '0fc0', 'xxxx' ) ) * 1024 );
      t_tmp := bitor32( t_tmp, bitand( raw1, to_number( 'fc0000', 'xxxxxx' ) ) / 1024 );
      t_tmp := bitor32( t_tmp, bitand( raw1, to_number( '0fc0', 'xxxx' ) ) / 64 );
      p_keys(knli) := t_tmp;
      knli := knli + 1;
      t_tmp := bitand( raw0, to_number( '03f000', 'xxxxxx' ) ) * 4096;
      t_tmp := bitor32( t_tmp, bitand( raw0, to_number( '3f', 'xx' ) ) * 65536 );
      t_tmp := bitor32( t_tmp, bitand( raw1, to_number( '03f000', 'xxxxxx' ) ) / 16 );
      t_tmp := bitor32( t_tmp, bitand( raw1, to_number( '3f', 'xx' ) ) );
      p_keys(knli) := t_tmp;
      knli := knli + 1;
    end loop;
  end;
--
  function des( p_block varchar2, p_keys tp_crypto )
  return varchar2
  is
    t_left  integer;
    t_right integer;
    t_tmp   integer;
    t_fval  integer;
  begin
    t_left := to_number( substr( p_block, 1, 8 ), 'XXXXXXXX' );
    t_right := to_number( substr( p_block, 9, 8 ), 'XXXXXXXX' );
    t_tmp := bitand( bitxor32( shr( t_left, 4 ), t_right ), to_number( '0f0f0f0f', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, shl( t_tmp, 4 ) );
    t_tmp := bitand( bitxor32( shr( t_left, 16 ), t_right ), to_number( '0000ffff', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, shl( t_tmp, 16 ) );
    t_tmp := bitand( bitxor32( shr( t_right, 2 ), t_left ), to_number( '33333333', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, shl( t_tmp, 2 ) );
    t_left := bitxor32( t_left, t_tmp );
    t_tmp := bitand( bitxor32( shr( t_right, 8 ), t_left ), to_number( '00ff00ff', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, shl( t_tmp, 8 ) );
    t_right := t_right * 2 + standard.sign( bitand( t_right, 2147483648 ) );
    t_left := bitxor32( t_left, t_tmp );
    t_tmp := bitand( bitxor32( t_right , t_left ), to_number( 'aaaaaaaa', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, t_tmp );
    t_left := t_left * 2 + standard.sign( bitand( t_left, 2147483648 ) );
--
    for i in 1 .. 8
    loop
      t_tmp := bitor32( shl( t_right, 28 ), shr( t_right, 4 ) );
      t_tmp := bitxor32( t_tmp, p_keys( i * 4 - 3 ) );
      t_fval := SP7( bitand( t_tmp, 63 ) + 1 );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP5( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP3( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP1( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := bitxor32( t_right, p_keys( i * 4 - 2 ) );
      t_fval := bitor32( t_fval, SP8( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP6( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP4( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP2( bitand( t_tmp, 63 ) + 1 ) );
      t_left := bitxor32( t_left, t_fval );
      t_tmp := bitor32( shl( t_left, 28 ), shr( t_left, 4 ) );
      t_tmp := bitxor32( t_tmp, p_keys( i * 4 - 1 ) );
      t_fval := SP7( bitand( t_tmp, 63 ) + 1 );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP5( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP3( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP1( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := bitxor32( t_left, p_keys( i * 4 ) );
      t_fval := bitor32( t_fval, SP8( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP6( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP4( bitand( t_tmp, 63 ) + 1 ) );
      t_tmp := shr( t_tmp, 8 );
      t_fval := bitor32( t_fval, SP2( bitand( t_tmp, 63 ) + 1 ) );
      t_right := bitxor32( t_right, t_fval );
    end loop;
--
    t_right := shl( t_right, 31 ) + shr( t_right, 1 );
    t_tmp := bitand( bitxor32( t_right , t_left ), to_number( 'aaaaaaaa', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, t_tmp );
    t_left := shl( t_left, 31 ) + shr( t_left, 1 );
    t_tmp := bitand( bitxor32( shr( t_left, 8 ), t_right ), to_number( '00ff00ff', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, shl( t_tmp, 8 ) );
    t_tmp := bitand( bitxor32( shr( t_left, 2 ), t_right ), to_number( '33333333', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, t_tmp );
    t_left := bitxor32( t_left, shl( t_tmp, 2 ) );
    t_tmp := bitand( bitxor32( shr( t_right, 16 ), t_left ), to_number( '0000ffff', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, shl( t_tmp, 16 ) );
    t_left := bitxor32( t_left, t_tmp );
    t_tmp := bitand( bitxor32( shr( t_right, 4 ), t_left ), to_number( '0f0f0f0f', 'xxxxxxxx' ) );
    t_right := bitxor32( t_right, shl( t_tmp, 4 ) );
    t_left := bitxor32( t_left, t_tmp );
--
    return to_char( t_right, 'fm0XXXXXXX' ) || to_char( t_left, 'fm0XXXXXXX' );
  end;
--
  function encrypt__rc4( src raw, key raw )
  return raw
  is
    type tp_arcfour_sbox is table of pls_integer index by pls_integer;
    type tp_arcfour is record
      (  s tp_arcfour_sbox
      ,  i pls_integer
      ,  j pls_integer
      );
    t_tmp pls_integer;
    t_s2 tp_arcfour_sbox;
    t_arcfour tp_arcfour;
    t_encr raw(32767);
  begin
    for  i in 0 .. 255
    loop
      t_arcfour.s(i) :=  i;
    end  loop;
    for  i in 0 .. 255
    loop
      t_s2(i) := to_number( utl_raw.substr( key, mod( i, utl_raw.length( key ) ) + 1, 1 ), 'XX' );
    end  loop;
    t_arcfour.j  := 0;
    for  i in 0 .. 255
    loop
      t_arcfour.j := mod( t_arcfour.j +  t_arcfour.s(i) + t_s2(i), 256 );
      t_tmp := t_arcfour.s(i);
      t_arcfour.s(i) :=  t_arcfour.s( t_arcfour.j );
      t_arcfour.s( t_arcfour.j ) := t_tmp;
    end  loop;
    t_arcfour.i  := 0;
    t_arcfour.j  := 0;
--
    for  i in 1 .. utl_raw.length( src )
    loop
      t_arcfour.i := bitand( t_arcfour.i + 1, 255 );
      t_arcfour.j := bitand( t_arcfour.j + t_arcfour.s(  t_arcfour.i ), 255 );
      t_tmp := t_arcfour.s( t_arcfour.i  );
      t_arcfour.s( t_arcfour.i ) := t_arcfour.s( t_arcfour.j );
      t_arcfour.s( t_arcfour.j ) := t_tmp;
      t_encr := utl_raw.concat( t_encr
                              , to_char( t_arcfour.s( bitand( t_arcfour.s( t_arcfour.i ) + t_arcfour.s( t_arcfour.j ), 255 ) ), 'fm0x' )
                              );
    end  loop;
    return utl_raw.bit_xor( src, t_encr );
  end;
--
  function encrypt( src raw, typ pls_integer, key raw, iv raw := null )
  return raw
  is
    t_keys tp_crypto;
    t_keys2 tp_crypto;
    t_keys3 tp_crypto;
    t_encrypt_key tp_aes_tab;
    t_idx pls_integer;
    t_len pls_integer;
    t_tmp varchar2(32766);
    t_tmp2 varchar2(32766);
    t_encr raw(32767);
    t_plain raw(32767);
    t_padding raw(65);
    t_pad pls_integer;
    t_iv raw(64);
    t_raw raw(64);
    t_bs pls_integer := 8;
    t_bs2 pls_integer;
    function encr( p raw )
    return raw
    is
      tmp raw(100);
    begin
      case bitand( typ, 15 )
        when ENCRYPT_3DES then
          tmp := des( des( des( p, t_keys ), t_keys2 ), t_keys3 );
        when ENCRYPT_DES then
          tmp := des( p, t_keys );
        when ENCRYPT_3DES_2KEY then
          tmp := des( des( des( p, t_keys ), t_keys2 ), t_keys3 );
        when ENCRYPT_AES then
          tmp := aes_encrypt( p, utl_raw.length( key ), t_encrypt_key );
        when ENCRYPT_AES128 then
          tmp := aes_encrypt( p, 16, t_encrypt_key );
        when ENCRYPT_AES192 then
          tmp := aes_encrypt( p, 24, t_encrypt_key );
        when ENCRYPT_AES256 then
          tmp := aes_encrypt( p, 32, t_encrypt_key );
        else
          tmp := p;
      end case;
      return tmp;
    end;
  begin
    if bitand( typ, 255 ) = ENCRYPT_RC4
    then
      return encrypt__rc4( src, key );
    end if;
    case bitand( typ, 15 ) -- 0x000F
      when ENCRYPT_3DES then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, true );
        deskey( utl_raw.substr( key, 9, 8 ), t_keys2, false );
        deskey( utl_raw.substr( key, 17, 8 ), t_keys3, true );
      when ENCRYPT_DES then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, true );
      when ENCRYPT_3DES_2KEY then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, true );
        deskey( utl_raw.substr( key, 9, 8 ), t_keys2, false );
        t_keys3 := t_keys;
      when ENCRYPT_AES then
        t_bs := 16;
        aes_encrypt_key( key, t_encrypt_key  );
      when ENCRYPT_AES128 then
        t_bs := 16;
        aes_encrypt_key( key, t_encrypt_key  );
      when ENCRYPT_AES192 then
        t_bs := 16;
        aes_encrypt_key( key, t_encrypt_key  );
      when ENCRYPT_AES256 then
        t_bs := 16;
        aes_encrypt_key( key, t_encrypt_key  );
      else
        null;
    end case;
    case bitand( typ, 61440 ) -- 0xF000
      when PAD_NONE then
        t_pad := mod( utl_raw.length( src ), t_bs );
        if t_pad > 0
        then
          t_padding := utl_raw.copies( '00', t_bs - t_pad );
        end if;
      when PAD_PKCS5 then
        t_pad := t_bs - mod( utl_raw.length( src ), t_bs );
        t_padding := utl_raw.copies( to_char( t_pad, 'fm0X' ), t_pad );
      when PAD_OneAndZeroes then -- OneAndZeroes Padding, ISO/IEC 7816-4
        t_pad := t_bs - 1 - mod( utl_raw.length( src ), t_bs );
        if t_pad = 0
        then
          t_padding := '80';
        else
          t_padding := utl_raw.concat( '80', utl_raw.copies( '00', t_pad ) );
        end if;
      when PAD_ANSI_X923 then -- ANSI X.923
        t_pad := t_bs - 1 - mod( utl_raw.length( src ), t_bs );
        if t_pad = 0
        then
          t_pad := t_bs;
        end if;
        t_padding := utl_raw.concat( utl_raw.copies( '00', t_pad ), to_char( t_pad, 'fm0X' ) );
      when PAD_ZERO then -- zero padding
        t_pad := mod( utl_raw.length( src ), t_bs );
        if t_pad > 0
        then
          t_padding := utl_raw.copies( '00', t_bs - t_pad );
        end if;
      when PAD_ORCL then -- zero padding
        t_pad := mod( utl_raw.length( src ), t_bs );
        if t_pad > 0
        then
          t_padding := utl_raw.copies( '00', t_bs - t_pad );
        end if;
      else
        null;
    end case;
    t_bs2 := t_bs * 2;
    t_plain := utl_raw.concat( src, t_padding );
    t_idx := 1;
    t_len := utl_raw.length( t_plain );
    t_iv := coalesce( iv, utl_raw.copies( '0', t_bs ) );
    while t_idx <= t_len
    loop
      t_tmp := rawtohex( utl_raw.substr( t_plain, t_idx, least( 16376, t_len - t_idx + 1 ) ) );
      t_idx := t_idx + 16376;
      t_tmp2 := null;
      for i in 0 .. trunc( length( t_tmp ) / t_bs2 ) - 1
      loop
        case bitand( typ, 3840 ) -- 0x0F00
          when CHAIN_CBC then
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
            t_raw := encr( t_raw );
            t_iv := t_raw;
          when CHAIN_CFB then
            t_iv := encr( t_iv );
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
            t_iv := t_raw;
          when CHAIN_ECB then
            t_raw := encr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
          when CHAIN_OFB then
$IF DBMS_DB_VERSION.VER_LE_10 $THEN
            t_raw := encr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
$ELSIF DBMS_DB_VERSION.VER_LE_11 $THEN
            t_raw := encr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
$ELSE
            t_iv := encr( t_iv );
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
$END
          when CHAIN_OFB_REAL then
            t_iv := encr( t_iv );
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
          else
            null;
        end case;
        t_tmp2 := t_tmp2 || t_raw;
      end loop;
      t_encr := utl_raw.concat( t_encr, hextoraw( t_tmp2 ) );
    end loop;
    case bitand( typ, 61440 ) -- 0xF000
      when PAD_NONE then
        t_encr := utl_raw.substr( t_encr, 1, utl_raw.length( src ) );
      when PAD_ORCL then
        t_encr := utl_raw.concat( t_encr, to_char( t_bs - mod( utl_raw.length( src ) - 1, t_bs ), 'fm0X' ) );
      else
        null;
    end case;
    return t_encr;
  end encrypt;
--
  function decrypt( src raw, typ pls_integer, key raw, iv raw := null )
  return raw
  is
    t_keys tp_crypto;
    t_keys2 tp_crypto;
    t_keys3 tp_crypto;
    t_decrypt_key tp_aes_tab;
    t_idx pls_integer;
    t_len pls_integer;
    t_tmp varchar2(32766);
    t_tmp2 varchar2(32766);
    t_decr raw(32767);
    t_pad pls_integer;
    t_iv raw(64);
    t_raw raw(64);
    t_bs pls_integer := 8;
    t_bs2 pls_integer;
    t_fb boolean;
    function decr( p raw )
    return raw
    is
      tmp raw(100);
    begin
      case bitand( typ, 15 ) -- 0x000F
        when ENCRYPT_3DES then
          tmp := des( des( des( p, t_keys3 ), t_keys2 ), t_keys );
        when ENCRYPT_DES then
          tmp := des( p, t_keys );
        when ENCRYPT_3DES_2KEY then
          tmp := des( des( des( p, t_keys3 ), t_keys2 ), t_keys );
        when ENCRYPT_AES then
          tmp := aes_decrypt( p, utl_raw.length( key ), t_decrypt_key );
        when ENCRYPT_AES128 then
          tmp := aes_decrypt( p, 16, t_decrypt_key );
        when ENCRYPT_AES192 then
          tmp := aes_decrypt( p, 24, t_decrypt_key );
        when ENCRYPT_AES256 then
          tmp := aes_decrypt( p, 32, t_decrypt_key );
        else
          tmp := p;
      end case;
      return tmp;
    end;
  begin
    if bitand( typ, 255 ) = ENCRYPT_RC4
    then
      return encrypt__rc4( src, key );
    end if;
$IF DBMS_DB_VERSION.VER_LE_10 $THEN
    t_fb := bitand( typ, 3840 ) in ( CHAIN_CFB, CHAIN_OFB_REAL );
$ELSIF DBMS_DB_VERSION.VER_LE_11 $THEN
    t_fb := bitand( typ, 3840 ) in ( CHAIN_CFB, CHAIN_OFB_REAL );
$ELSE
    t_fb := bitand( typ, 3840 ) in ( CHAIN_CFB, CHAIN_OFB, CHAIN_OFB_REAL );
$END
    case bitand( typ, 15 ) -- 0x000F
      when ENCRYPT_3DES then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, t_fb );
        deskey( utl_raw.substr( key, 9, 8 ), t_keys2, not t_fb );
        deskey( utl_raw.substr( key, 17, 8 ), t_keys3, t_fb );
      when ENCRYPT_DES then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, t_fb );
      when ENCRYPT_3DES_2KEY then
        deskey( utl_raw.substr( key, 1, 8 ), t_keys, t_fb );
        deskey( utl_raw.substr( key, 9, 8 ), t_keys2, not t_fb );
        t_keys3 := t_keys;
      when ENCRYPT_AES then
        t_bs := 16;
        aes_decrypt_key( key, t_decrypt_key  );
      when ENCRYPT_AES128 then
        t_bs := 16;
        aes_decrypt_key( key, t_decrypt_key  );
      when ENCRYPT_AES192 then
        t_bs := 16;
        aes_decrypt_key( key, t_decrypt_key  );
      when ENCRYPT_AES256 then
        t_bs := 16;
        aes_decrypt_key( key, t_decrypt_key  );
      else
        null;
    end case;
    t_idx := 1;
    t_len := utl_raw.length( src );
    t_iv := coalesce( iv, utl_raw.copies( '0', t_bs ) );
    t_bs2 := t_bs * 2;
    while t_idx <= t_len
    loop
      t_tmp := utl_raw.substr( src, t_idx, least( 16376, t_len - t_idx + 1 ) );
      if (   bitand( typ, 61440 ) = PAD_NONE
         and mod( utl_raw.length( t_tmp ), t_bs ) != 0
         )
      then
        t_tmp := utl_raw.concat( t_tmp, utl_raw.copies( '00', t_bs - mod( utl_raw.length( t_tmp ), t_bs ) ) );
      end if;
      t_idx := t_idx + 16376;
      t_tmp2 := null;
      for i in 0 .. length( t_tmp ) / t_bs2 - 1
      loop
        case bitand( typ, 3840 ) -- 0x0F00
          when CHAIN_CBC then
            t_raw := decr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
            t_raw := utl_raw.bit_xor( t_raw, t_iv );
            t_iv := substr( t_tmp, i * t_bs2 + 1, t_bs2 );
          when CHAIN_CFB then
            t_raw := decr( t_iv );
            t_iv := substr( t_tmp, i * t_bs2 + 1, t_bs2 );
            t_raw := utl_raw.bit_xor( t_raw, t_iv );
          when CHAIN_OFB then
$IF DBMS_DB_VERSION.VER_LE_10 $THEN
            t_raw := decr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
$ELSIF DBMS_DB_VERSION.VER_LE_11 $THEN
            t_raw := decr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
$ELSE
            t_iv := decr( t_iv );
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
$END
          when CHAIN_OFB_REAL then
            t_iv := decr( t_iv );
            t_raw := utl_raw.bit_xor( substr( t_tmp, i * t_bs2 + 1, t_bs2 ), t_iv );
          when CHAIN_ECB then
            t_raw := decr( substr( t_tmp, i * t_bs2 + 1, t_bs2 ) );
        end case;
        t_tmp2 := t_tmp2 || t_raw;
      end loop;
      t_decr := utl_raw.concat( t_decr, hextoraw( t_tmp2 ) );
    end loop;
    case bitand( typ, 61440 ) -- 0xF000
      when PAD_PKCS5 then
        t_pad := to_number( utl_raw.substr( t_decr, -1 ), 'XX' );
        t_pad := utl_raw.length( t_decr ) - t_pad;
        t_decr := utl_raw.substr( t_decr, 1, t_pad );
      when PAD_OneAndZeroes then -- OneAndZeroes Padding, ISO/IEC 7816-4
        t_pad := length( t_tmp2 ) - instr( t_tmp2, '80', -1 ) + 1;
        t_pad := utl_raw.length( t_decr ) - t_pad / 2;
        t_decr := utl_raw.substr( t_decr, 1, t_pad );
      when PAD_ANSI_X923 then -- ANSI X.923
        t_pad := to_number( utl_raw.substr( t_decr, -1 ), 'XX' );
        t_pad := utl_raw.length( t_decr ) - t_pad - 1;
        t_decr := utl_raw.substr( t_decr, 1, t_pad );
      when PAD_ZERO then -- zero padding
        t_pad := length( t_tmp2 ) - length( rtrim( t_tmp2, '0' ) );
        t_pad := trunc( t_pad / 2 );
        if t_pad > 0
        then
          t_pad := utl_raw.length( t_decr ) - t_pad;
          t_decr := utl_raw.substr( t_decr, 1, t_pad );
        end if;
      when PAD_ORCL then -- zero padding
        t_pad := length( t_tmp2 ) - length( rtrim( t_tmp2, '0' ) );
        t_pad := trunc( t_pad / 2 );
        if t_pad > 0
        then
          t_pad := utl_raw.length( t_decr ) - t_pad;
          t_decr := utl_raw.substr( t_decr, 1, t_pad );
        end if;
      when PAD_NONE then
        t_decr := utl_raw.substr( t_decr, 1, t_len );
      else
        null;
    end case;
    return t_decr;
  end decrypt;
  --
  function gcm_aes( p_encrypt boolean, p_src raw, p_key raw, p_iv raw, p_aad raw, p_tag out raw )
  return raw
  is
    l_counter raw(3999);
    l_encrypted raw(3999);
    l_src_txt raw(3999);
    l_encr_ctr raw(3999);
    l_encr_txt raw(3999);
    l_H raw(3999);
    l_tag_init raw(3999);
    l_tag_tmp raw(3999);
    l_len pls_integer;
    l_encr_len pls_integer;
    l_block_size pls_integer := 16;
    l_mode pls_integer := ENCRYPT_AES + CHAIN_CBC + PAD_ZERO;
    type tp_ghash_precomp is table of boolean index by pls_integer;
    l_ghash_precomp tp_ghash_precomp;
    l_x number;                                                                                            
--
    function ghash( p_b varchar2 )                                                             
    return varchar2                                                                                          
    is                                                                                                       
      l_v raw(16);                                                                                           
      l_z raw(16);                                                                                           
      l_reduce boolean;                                                                                      
      l_v0 number;                                                                                             
      l_v1 number;                                                                                           
    begin
      l_z := utl_raw.copies( '00', 16 );                                                                           
      for i in 0 .. trunc( length( p_b ) / 32 ) - 1
      loop
        l_v := lpad( substr( p_b, 1 + i * 32, 32 ), 32, '0' );
        l_v := utl_raw.bit_xor( l_v, l_z );
        l_z := utl_raw.copies( '00', 16 );                                                                           
        for i in 0 .. 1                                                                                        
        loop                                                                                                   
          for j in 0 .. 63 - i                                                                                 
          loop                                                                                                 
            if l_ghash_precomp( i * 64 + j )
            then                                                                                               
              l_z := utl_raw.bit_xor( l_z, l_v );                                                              
            end if;                                                                                            
            l_v0 := to_number( substr( rawtohex( l_v ), 1, 16 ), rpad( 'X', 16, 'X' ) );                       
            l_v1 := to_number( substr( rawtohex( l_v ), -16 ), rpad( 'X', 16, 'X' ) );                         
            l_reduce := bitand( l_v1, 1 ) > 0;                                                                 
            l_v1 := trunc( l_v1 / 2 ) + case when bitand( l_v0, 1 ) > 0 then 9223372036854775808 else 0 end;   
            l_v := to_char( trunc( l_v0 / 2 ), 'FM' || rpad( '0', 16, 'X' ) )                                  
                || to_char( l_v1, 'FM' || rpad( '0', 16, 'X' ) );                                              
            if l_reduce                                                                                        
            then                                                                                               
              l_v := utl_raw.bit_xor( l_v, 'E1000000000000000000000000000000' );                               
            end if;                                                                                            
          end loop;                                                                                            
        end loop;                                                                                              
        if l_ghash_precomp( 127 )
        then                                                                                                   
          l_z := utl_raw.bit_xor( l_z, l_v );                                                                  
        end if;
      end loop;
      return l_z;                                                                                            
    end;                                                                                                     
  --
  begin
    l_H := encrypt( utl_raw.copies( '00', l_block_size ), l_mode, p_key );
    for i in 0 .. 1                                                                                        
    loop                                                                                                   
      l_x := to_number( substr( lpad( l_H, 32, '0' ), 1 + i * 16, 16 ), lpad( 'X', 16, 'X' ) );            
      for j in 0 .. 63                                                                               
      loop
        l_ghash_precomp( i * 64 + j ) := bitand( l_x, power( 2, 63 - j ) ) != 0;
      end loop;
    end loop;
    l_len := nvl( utl_raw.length( p_iv ), 0 );
    if l_len != 12
    then
      if p_iv is null
      then
        l_counter := utl_raw.copies( '00', 3 * l_block_size - 1  ) || '00';
      else
        if mod( l_len, l_block_size ) > 0
        then
          l_counter := utl_raw.copies( '00', l_block_size - mod( l_len, l_block_size ) );
        end if;
        l_counter := utl_raw.concat( p_iv
                                   , l_counter
                                   , utl_raw.copies( '00', 8 )
                                   , to_char( 8 * l_len, 'fm0XXXXXXXXXXXXXXX' )
                                   );
      end if;
      l_counter := ghash( l_counter );
    else
      l_counter := utl_raw.concat( p_iv, utl_raw.copies( '00', l_block_size - 13 ), '01' );
    end if;
    l_tag_init := encrypt( l_counter, l_mode, p_key );
    l_tag_tmp := ghash( utl_raw.substr( utl_raw.concat( p_aad, utl_raw.copies( '00', l_block_size ) ), 1, l_block_size ) );
    l_len := nvl( utl_raw.length( p_src ), 0 );
    if not p_encrypt
    then
      l_len := l_len - l_block_size;
    end if;
    for i in 0 .. trunc( l_len / l_block_size ) - 1
    loop
      l_counter := utl_raw.concat( utl_raw.substr( l_counter, 1, l_block_size - 4 )
                                 , to_char( to_number( utl_raw.substr( l_counter, - 4 ), '0XXXXXXX' ) + 1, 'fm0XXXXXXX' )
                                 );
      l_encr_ctr := encrypt( l_counter, l_mode, p_key );
      l_src_txt := utl_raw.substr( p_src, 1 + i * l_block_size, l_block_size );
      l_encr_txt := utl_raw.bit_xor( l_src_txt, l_encr_ctr );
      if p_encrypt
      then
        l_tag_tmp := ghash( utl_raw.bit_xor( l_encr_txt, l_tag_tmp ) );
      else
        l_tag_tmp := ghash( utl_raw.bit_xor( l_src_txt, l_tag_tmp ) );
      end if;
      l_encrypted := utl_raw.concat( l_encrypted, l_encr_txt );
    end loop;
    l_encr_len := nvl( utl_raw.length( l_encrypted ), 0 );
    if l_encr_len < l_len
    then
      l_counter := utl_raw.concat( utl_raw.substr( l_counter, 1, l_block_size - 4 )
                                 , to_char( 1 + to_number( utl_raw.substr( l_counter, -4 ), '0XXXXXXX' ), 'fm0XXXXXXX' )
                                 );
      l_encr_ctr := encrypt( l_counter, l_mode, p_key );
      if p_encrypt
      then
        l_src_txt := utl_raw.substr( p_src, l_encr_len - l_len );
      else
        l_src_txt := utl_raw.substr( p_src, l_encr_len - l_len - l_block_size, l_len - l_encr_len );
      end if;
      l_encr_txt := utl_raw.bit_xor( l_src_txt, l_encr_ctr );
      l_encr_txt := utl_raw.substr( l_encr_txt, 1, l_len - l_encr_len );
      if p_encrypt
      then
        l_tag_tmp := ghash( utl_raw.bit_xor( l_encr_txt, l_tag_tmp ) );
      else
        l_tag_tmp := ghash( utl_raw.bit_xor( l_src_txt, l_tag_tmp ) );
      end if;
      l_encrypted := utl_raw.concat( l_encrypted, l_encr_txt );
    end if;
    l_tag_tmp := ghash( utl_raw.bit_xor( to_char( nvl( utl_raw.length( p_aad ), 0 ) * 8, 'fm0XXXXXXXXXXXXXXX' )
                                      || to_char( l_len * 8, 'fm0XXXXXXXXXXXXXXX' )
                                       , l_tag_tmp
                                       ) 
                      );
    l_tag_tmp := utl_raw.bit_xor( l_tag_init, l_tag_tmp );
    if p_encrypt
    then
      p_tag := l_tag_tmp;
    elsif utl_raw.substr( p_src, - l_block_size ) != l_tag_tmp
    then
      raise_application_error( -20039, 'Authentication Tag has is not as expected.' );
    end if;
    return l_encrypted;
  end;
  --
  function encrypt( src in  raw
                  , typ in  pls_integer
                  , key in  raw
                  , iv  in  raw := null
                  , aad in  raw := null
                  , tag out raw
                  )
  return raw
  is
  begin
    if typ is null
    then
      raise_application_error( -20030, 'no cipher type specified' );
    elsif bitand( typ, 61440 ) != PAD_NONE -- 0xF000
    then
      raise_application_error( -20031, 'An invalid cipher type was passed to a PL/SQL function or procedure.' );
    elsif bitand( typ, 3840 ) != CHAIN_GCM -- 0x0F00
    then
      raise_application_error( -20032, 'An invalid cipher type was passed to a PL/SQL function or procedure.' );
    elsif bitand( typ, 255 ) not in ( ENCRYPT_AES, ENCRYPT_AES128, ENCRYPT_AES192, ENCRYPT_AES256 )  -- 0x0FF
    then
      raise_application_error( -20033, 'Chaining mode GCM is only allowed for AES encryption.' );
    elsif iv is null
    then
      raise_application_error( -20034, 'GCM requires a iv nonce.' );
    end if;
    return gcm_aes( true, src, key, iv, aad, tag );
  end encrypt;
  --
  function decrypt( src in raw
                  , typ in pls_integer
                  , key in raw
                  , iv  in raw := null
                  , aad in raw := null
                  , tag in raw
                  )
  return raw
  is
    l_dummy_tag raw(3999);
  begin
    if typ is null
    then
      raise_application_error( -20030, 'no cipher type specified' );
    elsif bitand( typ, 61440 ) != PAD_NONE -- 0xF000
    then
      raise_application_error( -20031, 'An invalid cipher type was passed to a PL/SQL function or procedure.' );
    elsif bitand( typ, 3840 ) != CHAIN_GCM -- 0x0F00
    then
      raise_application_error( -20032, 'An invalid cipher type was passed to a PL/SQL function or procedure.' );
    elsif bitand( typ, 255 ) not in ( ENCRYPT_AES, ENCRYPT_AES128, ENCRYPT_AES192, ENCRYPT_AES256 )  -- 0x0FF
    then
      raise_application_error( -20033, 'Chaining mode GCM is only allowed for AES encryption.' );
    elsif iv is null
    then
      raise_application_error( -20034, 'GCM requires a iv nonce.' );
    end if;
    return gcm_aes( false, utl_raw.concat( src, tag ), key, iv, aad, l_dummy_tag );
  end decrypt;
  --
  function rsa_chinese_remainder( p_m tp_mag
                                , p_key_parameters in out tp_key_parameters
                                )
  return raw
  is
    l_m1 tp_mag;
    l_m2 tp_mag;
    l_h tp_mag;
    l_p tp_mag;
    l_q tp_mag;
  begin
    if p_key_parameters.exists(6)
    then
      if not p_key_parameters.exists(8)
      then
        p_key_parameters(7) := demag( xmod( mag( p_key_parameters(3) ), nsub( mag( p_key_parameters(5) ), 1 ) ) );
        p_key_parameters(8) := demag( xmod( mag( p_key_parameters(3) ), nsub( mag( p_key_parameters(6) ), 1 ) ) );
      end if;
      l_p := mag( p_key_parameters(5) ); -- prime1
      l_q := mag( p_key_parameters(6) ); -- prime2
      l_m1 := powmod( p_m, mag( p_key_parameters(7) ), l_p ); -- (7) = dp
      l_m2 := powmod( p_m, mag( p_key_parameters(8) ), l_q ); -- (8) = dq
      l_h := mulmod( submod(l_m1, l_m2, l_p ), mag( p_key_parameters(4) ), l_p );   -- (4) = qinv
      return demag( addmod( l_m2, rmul( l_h, l_q ), mag( p_key_parameters(1) ) ) ); -- (1) = n
    end if;    
    return demag( powmod( p_m, mag( p_key_parameters(3) ), mag( p_key_parameters(1) ) ) );
  end;
  --
  function pkEncrypt( src raw
                    , pub_key raw
                    , pubkey_alg binary_integer
                    , enc_alg binary_integer
                    )
  return raw
  is
    -- https://tools.ietf.org/html/rfc8017#section-7.1.1
    l_rv raw(32767);
    l_key_parameters tp_key_parameters;
    l_k pls_integer;
    l_ml pls_integer;
    l_k0 pls_integer;
    l_hash_type pls_integer;
    l_x raw(32767);
    l_y raw(32767);
    l_em raw(32767);
    l_r raw(3999);
    l_empty_hash raw(3999);
  begin
    if src is null
    then
      raise_application_error( -20010, 'No input buffer provided.' );
    elsif pub_key is null
    then
      raise_application_error( -20011, 'no key provided' );
    elsif pubkey_alg is null
    then
      raise_application_error( -20012, 'PL/SQL function returned an error.' );
    elsif pubkey_alg != KEY_TYPE_RSA
    then
      raise_application_error( -20013, 'invalid cipher type passed' );
    elsif enc_alg is null
    then
      raise_application_error( -20014, 'PL/SQL function returned an error.' );
    elsif enc_alg not in ( PKENCRYPT_RSA_PKCS1_OAEP, PKENCRYPT_RSA_PKCS1_OAEP_SHA2 )
    then
      raise_application_error( -20015, 'invalid cipher type passed' );
    elsif not parse_DER_RSA_PUB_key( base64_decode( pub_key ), l_key_parameters )
    then
      raise_application_error( -20016, 'PL/SQL function returned an error.' );
    end if;
    l_hash_type := case enc_alg when PKENCRYPT_RSA_PKCS1_OAEP_SHA2 then HASH_SH256 else HASH_SH256 end;
    l_empty_hash := hash( null, l_hash_type );
    l_k0 := utl_raw.length( l_empty_hash );
    l_k := trunc( utl_raw.length( l_key_parameters(1) ) / 8 ) * 8;
    l_ml := utl_raw.length( src );
    if l_ml > l_k - 2 * l_k0 - 2
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    l_x := utl_raw.concat( l_empty_hash
                         , case when l_k - 2 * l_k0 - 2 - l_ml > 0 then utl_raw.copies( '00', l_k - 2 * l_k0 - 2 - l_ml ) end
                         , '01'
                         , src
                         );
    l_r := randombytes( l_k0 );
    l_y := utl_raw.bit_xor( l_x, mgf1( l_r, l_k - l_k0 - 1, l_hash_type ) );
    l_em := utl_raw.concat( utl_raw.bit_xor( mgf1( l_y, l_k0, l_hash_type ), l_r ), l_y );
    l_rv := demag( powmod( mag( l_em ), mag( l_key_parameters(2) ), mag( l_key_parameters(1) ) ) );
    return l_rv;
  end;
  --
  function pkDecrypt( src raw
                    , prv_key raw
                    , pubkey_alg binary_integer
                    , enc_alg binary_integer
                    )
  return raw
  is
    -- https://tools.ietf.org/html/rfc8017#section-7.1.2
    l_rv raw(32767);
    l_k pls_integer;
    l_k0 pls_integer;
    l_hash_type pls_integer;
    l_em raw(32767);
    l_x raw(32767);
    l_tmp raw(1);
    l_r raw(3999);
    l_idx pls_integer;
    l_key_parameters tp_key_parameters;
    l_empty_hash raw(3999);
  begin
    if src is null
    then
      raise_application_error( -20010, 'No input buffer provided.' );
    elsif prv_key is null
    then
      raise_application_error( -20011, 'no key provided' );
    elsif pubkey_alg is null
    then
      raise_application_error( -20012, 'PL/SQL function returned an error.' );
    elsif pubkey_alg != KEY_TYPE_RSA
    then
      raise_application_error( -20013, 'invalid cipher type passed' );
    elsif enc_alg is null
    then
      raise_application_error( -20014, 'PL/SQL function returned an error.' );
    elsif enc_alg not in ( PKENCRYPT_RSA_PKCS1_OAEP, PKENCRYPT_RSA_PKCS1_OAEP_SHA2 )
    then
      raise_application_error( -20015, 'invalid cipher type passed' );
    elsif not parse_DER_RSA_PRIV_key( base64_decode( prv_key ), l_key_parameters )
    then
      raise_application_error( -20016, 'PL/SQL function returned an error.' );
    end if;
    l_k := utl_raw.length( src );
    if l_k > utl_raw.length( l_key_parameters(1) )
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    l_hash_type := case enc_alg when PKENCRYPT_RSA_PKCS1_OAEP_SHA2 then HASH_SH256 else HASH_SH256 end;
    l_empty_hash := hash( null, l_hash_type );
    l_k0 := utl_raw.length( l_empty_hash );
    l_em := rsa_chinese_remainder( mag( src ), l_key_parameters );
  --  l_em := demag( powmod( mag( src ), mag( l_key_parameters(3) ), mag( l_key_parameters(1) ) ) );
    if utl_raw.length( l_em ) < l_k
    then
      l_em := utl_raw.concat( utl_raw.copies( '00', l_k - utl_raw.length( l_em ) ), l_em );
    end if;
    if utl_raw.substr( l_em, 1, 1 ) != '00'
    then
      raise_application_error( -20018, 'PL/SQL function returned an error.' );
    end if;
    l_x := utl_raw.substr( l_em, 2 + l_k0 );
    l_r := utl_raw.bit_xor( utl_raw.substr( l_em, 2, l_k0 ), mgf1( l_x, l_k0, l_hash_type ) );
    l_rv := utl_raw.bit_xor( l_x, mgf1( l_r, l_k - l_k0 - 1, l_hash_type ) );
    if utl_raw.substr( l_rv, 1, l_k0 ) != l_empty_hash
    then
      raise_application_error( -20019, 'PL/SQL function returned an error.' );
    end if;
    for i in l_k0 + 1 .. utl_raw.length( l_rv )
    loop
      l_idx := i;
      l_tmp := utl_raw.substr( l_rv, i, 1 );
      exit when l_tmp = '01';
      if l_tmp != '00'
      then
        raise_application_error( -20020, 'PL/SQL function returned an error.' );
      end if;
    end loop;
    return utl_raw.substr( l_rv, l_idx + 1 );
  end;
  --
  function get_rsa_pss_mask( p_mod raw )
  return raw
  is
    l_fist_octect pls_integer;
  begin
    l_fist_octect := to_number( utl_raw.substr( p_mod, 1, 1 ), 'XX' );
    return case
             when bitand( l_fist_octect, 128 ) > 0 then '7F'
             when bitand( l_fist_octect, 64 ) > 0 then '3F'
             when bitand( l_fist_octect, 32 ) > 0 then '1F'
             when bitand( l_fist_octect, 16 ) > 0 then '0F'
             when bitand( l_fist_octect, 8 ) > 0 then '07'
             when bitand( l_fist_octect, 4 ) > 0 then '03'
             when bitand( l_fist_octect, 2 ) > 0 then '01'
             else 'FF'
           end;
  end;
  --
  function sign_rsa( src raw
                   , prv_key raw
                   , pubkey_alg binary_integer
                   , sign_alg binary_integer
                   )
  return raw
  is
    l_sz pls_integer;
    l_tmp raw(3999);
    l_min tp_mag;
    l_mod tp_mag;
    l_msg tp_mag;
    l_key_parameters tp_key_parameters;
  begin
    if sign_alg not in ( SIGN_SHA224_RSA
                       , SIGN_SHA256_RSA
                       , SIGN_SHA256_RSA_X931
                       , SIGN_SHA384_RSA
                       , SIGN_SHA384_RSA_X931
                       , SIGN_SHA512_RSA
                       , SIGN_SHA512_RSA_X931
                       , SIGN_SHA1_RSA
                       , SIGN_SHA1_RSA_X931
                       , SIGN_MD2_RSA
                       , SIGN_MD5_RSA
                       , SIGN_SHA256_RSA_PSS
                       , SIGN_SHA384_RSA_PSS
                       , SIGN_SHA512_RSA_PSS
                       )
    then
      raise_application_error( -20015, 'invalid cipher type passed' );
    elsif not parse_DER_RSA_PRIV_key( base64_decode( prv_key ), l_key_parameters )
    then
      raise_application_error( -20016, 'PL/SQL function returned an error.' );
    elsif trunc( utl_raw.length( l_key_parameters(1) ) / 8 ) * 8 < 128
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    l_mod := mag( l_key_parameters(1) );
    l_sz := trunc( utl_raw.length( l_key_parameters(1) ) / 8 ) * 8;
    if sign_alg in ( SIGN_SHA256_RSA_X931
                   , SIGN_SHA384_RSA_X931
                   , SIGN_SHA512_RSA_X931
                   , SIGN_SHA1_RSA_X931
                   )
    then
      if sign_alg = SIGN_SHA1_RSA_X931
      then
        l_tmp := utl_raw.concat( hash( src, HASH_SH1 ), c_X931_TRAILER_SH1 );
      elsif sign_alg = SIGN_SHA512_RSA_X931
      then
        l_tmp := utl_raw.concat( hash( src, HASH_SH512 ), c_X931_TRAILER_SH512 );
      elsif sign_alg = SIGN_SHA256_RSA_X931
      then
        l_tmp := utl_raw.concat( hash( src, HASH_SH256 ), c_X931_TRAILER_SH256 );
      elsif sign_alg = SIGN_SHA384_RSA_X931
      then
        l_tmp := utl_raw.concat( hash( src, HASH_SH384 ), c_X931_TRAILER_SH384 );
      end if;
      l_tmp := utl_raw.concat( '6B', utl_raw.copies( 'BB', l_sz - utl_raw.length( l_tmp ) - 2 ), 'BA', l_tmp );
      l_msg := mag( l_tmp );
      l_min := rsub( l_mod, l_msg );
      if r_greater_equal( l_msg, l_min )
      then
        l_msg := l_min;
      end if;
    elsif sign_alg in ( SIGN_SHA256_RSA_PSS
                      , SIGN_SHA384_RSA_PSS
                      , SIGN_SHA512_RSA_PSS
                      )
    then
      declare
        l_hash_type pls_integer;
        l_em_len pls_integer;
        l_mask raw(1);
        l_first varchar2(2);
        l_h raw(3999);
        l_mh raw(3999);
        l_db raw(3999);
        l_salt raw(3999);
        l_masked raw(3999);
        l_hlen pls_integer;
      begin
        l_hash_type := case sign_alg
                         when SIGN_SHA256_RSA_PSS then HASH_SH256
                         when SIGN_SHA512_RSA_PSS then HASH_SH512
                         when SIGN_SHA384_RSA_PSS then HASH_SH384
                       end;
        l_hlen := case sign_alg
                    when SIGN_SHA256_RSA_PSS then 32
                    when SIGN_SHA512_RSA_PSS then 64
                    when SIGN_SHA384_RSA_PSS then 48
                  end;
        l_key_parameters(1) := demag( l_mod ); -- get rid of any leading 00
        l_em_len := utl_raw.length( l_key_parameters(1) );
        l_first := utl_raw.substr( l_key_parameters(1), 1, 1 );
        if l_first = '01'
        then
          l_em_len := l_em_len - 1;
        end if;
        l_mh := hash( src, l_hash_type );
        l_salt := randombytes( l_hlen );
        l_h := hash( utl_raw.concat( utl_raw.copies( '00', 8 )
                                   , l_mh
                                   , l_salt
                                   )
                   , l_hash_type
                   );
        l_db := utl_raw.concat( utl_raw.copies( '00', l_em_len - 2 * l_hlen - 2 )
                              , '01'
                              , l_salt
                              );
        l_masked := mgf1( l_h, l_em_len - l_hlen - 1, l_hash_type );
        l_tmp := utl_raw.concat( utl_raw.bit_xor( l_db, l_masked ), l_h , 'BC' );
        l_msg := mag( utl_raw.bit_and( l_tmp, get_rsa_pss_mask( l_first ) ) );
      end;
    else
      if sign_alg = SIGN_SHA1_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_SH1, hash( src, HASH_SH1 ) );
      elsif sign_alg = SIGN_SHA512_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_SH512, hash( src, HASH_SH512 ) );
      elsif sign_alg = SIGN_SHA256_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_SH256, hash( src, HASH_SH256 ) );
      elsif sign_alg = SIGN_SHA384_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_SH384, hash( src, HASH_SH384 ) );
      elsif sign_alg = SIGN_SHA224_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_SH224, hash( src, HASH_SH224 ) );
      elsif sign_alg = SIGN_MD2_RSA
      then
        l_tmp := utl_raw.concat( c_ASN1_MD2, hash( src, HASH_MD2 ) );
      end if;
      l_tmp := utl_raw.concat( '01', utl_raw.copies( 'FF', l_sz - utl_raw.length( l_tmp ) - 3 ), '00', l_tmp );
      l_msg := mag( l_tmp );
    end if;
    return rsa_chinese_remainder( l_msg, l_key_parameters );
    return demag( powmod( l_msg, mag( l_key_parameters(3) ), l_mod ) );
  end;
  --
  function sign_ec( src raw
                  , prv_key raw
                  , pubkey_alg binary_integer
                  , sign_alg binary_integer
                  )
  return raw
  is
    l_hash_type pls_integer;
    l_curve tp_ec_curve;
    l_xxx tp_mag;
    l_inv tp_mag;
    l_r tp_mag;
    l_s tp_mag;
    l_pb tp_ec_point;
    l_rv raw(3999);
    l_len pls_integer;
    l_key_parameters tp_key_parameters;
    --
    function mag2asn1( p_x tp_mag )
    return raw
    is
      l_tmp raw(3999);
    begin
      l_tmp := demag( p_x );
      if utl_raw.bit_and( utl_raw.substr( l_tmp, 1, 1 ), '80' ) = '80'
      then
        l_tmp := utl_raw.concat( '00', l_tmp );
      end if;
      return utl_raw.concat( c_INTEGER
                           , to_char( utl_raw.length( l_tmp ), 'fm0X' )
                           , l_tmp
                           );
    end;
  begin
    if sign_alg not in ( SIGN_SHA256withECDSA
                       , SIGN_SHA384withECDSA
                       , SIGN_SHA512withECDSA
                       , SIGN_SHA256withECDSAinP1363
                       , SIGN_SHA384withECDSAinP1363
                       , SIGN_SHA512withECDSAinP1363
                       )
    then
      raise_application_error( -20015, 'invalid cipher type passed' );
    elsif not parse_DER_EC_PRIV_key( base64_decode( prv_key ), l_key_parameters )
    then
      raise_application_error( -20016, 'PL/SQL function returned an error.' );
    end if;
    get_named_curve( utl_raw.cast_to_varchar2( l_key_parameters(1) ), l_curve );
    l_hash_type := case sign_alg
                     when SIGN_SHA256withECDSA then HASH_SH256
                     when SIGN_SHA384withECDSA then HASH_SH384
                     when SIGN_SHA512withECDSA then HASH_SH512
                     when SIGN_SHA256withECDSAinP1363 then HASH_SH256
                     when SIGN_SHA384withECDSAinP1363 then HASH_SH384
                     when SIGN_SHA512withECDSAinP1363 then HASH_SH512
                   end;
    l_xxx := xmod( mag( randombytes( l_curve.nlen ) ), l_curve.group_order );
    l_pb  := multiply_point( l_curve.generator, l_xxx, l_curve );
    l_r := xmod( l_pb.x, l_curve.group_order );
    l_inv := powmod( l_xxx, nsub( l_curve.group_order, 2 ), l_curve.group_order );
    l_s := mulmod( radd( mag( hash( src, l_hash_type ) )
                       , mulmod( mag( l_key_parameters(2) )
                               , l_r
                               , l_curve.group_order
                               )
                       )
                 , l_inv
                 , l_curve.group_order
                 );
    if sign_alg in ( SIGN_SHA256withECDSA
                   , SIGN_SHA384withECDSA
                   , SIGN_SHA512withECDSA
                   )
    then
      l_rv := utl_raw.concat( mag2asn1( l_r )
                            , mag2asn1( l_s )
                            );
      l_len := utl_raw.length( l_rv );
      if l_len < 128
      then
        l_rv := utl_raw.concat( '30' || to_char( l_len, 'fm0X' )
                              , l_rv
                              );
      else
        l_rv := utl_raw.concat( '3081' || to_char( l_len, 'fm0X' )
                              , l_rv
                              );
      end if;
    else
      l_rv := utl_raw.concat( lpad( demag( l_r ), 2 * l_curve.nlen, '0' )
                            , lpad( demag( l_s ), 2 * l_curve.nlen, '0' )
                            );
    end if;
    return l_rv;
  end;
  --
  function sign_eddsa( src raw
                     , prv_key raw
                     , pubkey_alg binary_integer
                     , sign_alg binary_integer
                     )
  return raw
  is
    l_hash_type pls_integer;
    l_curve tp_ed_curve;
    l_pkh raw(3999);
    l_a raw(3999);
    l_h raw(3999);
    l_r raw(3999);
    l_s raw(3999);
    l_rb raw(3999);
    l_ge tp_ed_point;
    l_hm tp_mag;
    l_inv tp_mag;
    l_rbytes tp_mag;
    l_key_parameters tp_key_parameters;
  begin
    if sign_alg not in ( SIGN_Ed25519 )
    then
      raise_application_error( -20016, 'invalid cipher type passed' );
    elsif not parse_DER_EDDSA_priv_key( base64_decode( prv_key ), l_key_parameters )
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    -- https://datatracker.ietf.org/doc/html/draft-josefsson-eddsa-ed25519-02#section-5.6
    get_named_ed_curve( utl_raw.cast_to_varchar2( l_key_parameters(1) ), l_curve );
    l_hash_type := HASH_SH512;
    l_pkh := hash( utl_raw.substr( l_key_parameters(2), 1, l_curve.nlen ), l_hash_type );
    l_pkh := utl_raw.bit_and( utl_raw.concat( 'F8', utl_raw.copies( 'FF', l_curve.nlen - 2 ), '3F' ), l_pkh );
    l_pkh := utl_raw.bit_or( utl_raw.concat( utl_raw.copies( '00', l_curve.nlen - 1 ), '40' ), l_pkh );
    l_r := hash( utl_raw.concat( utl_raw.substr( l_pkh, - l_curve.nlen ), src ), l_hash_type );
    l_r := demag( xmod( mag( utl_raw.reverse( l_r ) ), l_curve.l ) );
    l_ge := ed_scalarmultiply( l_curve.b, l_curve, mag( l_r ) );
    l_inv := powmod( l_ge.z, nsub( l_curve.q, 2 ), l_curve.q );
    l_rbytes := mulmod( l_ge.y, l_inv, l_curve.q );
    l_rb := substr( lpad( demag( l_rbytes ), l_curve.nlen * 2, '0' ), - l_curve.nlen * 2 );
    if bitand( mulmod( l_ge.x, l_inv, l_curve.q )(0), 1 ) = 1 then
        l_rb := utl_raw.bit_or( '80', l_rb );
    end if;
    l_rb := utl_raw.reverse( l_rb );
    l_a := utl_raw.substr( hash( l_key_parameters(2), HASH_SH512 ), 1, l_curve.nlen );
    l_a := utl_raw.bit_and( utl_raw.concat( 'F8', utl_raw.copies( 'FF', l_curve.nlen - 2 ), '3F' ), l_a );
    l_a := utl_raw.bit_or( utl_raw.concat( utl_raw.copies( '00', l_curve.nlen - 1 ), '40' ), l_a );
    l_a := utl_raw.reverse( l_a );
    l_h := hash( utl_raw.concat( l_rb
                               , utl_raw.reverse( ed_point2bytes( ed_scalarmultiply( l_curve.b, l_curve, mag( l_a ) ), l_curve ) )
                               , src
                               )
               , l_hash_type
               );
    l_hm := xmod( mag( utl_raw.reverse( l_h ) ), l_curve.l );
    l_s := demag( addmod( mulmod( l_hm
                                , mag( utl_raw.reverse( utl_raw.substr( l_pkh, 1, l_curve.nlen ) ) )
                                , l_curve.l
                                )
                        , mag( l_r )
                        , l_curve.l
                        )
                );
    l_s := substr( lpad( l_s, l_curve.nlen * 2, '0' ), - l_curve.nlen * 2 );
    return utl_raw.concat( l_rb, utl_raw.reverse( l_s ) );
  end;
  --
  function sign( src raw
               , prv_key raw
               , pubkey_alg binary_integer
               , sign_alg binary_integer
               )
  return raw
  is
    l_sz pls_integer;
    l_tmp raw(3999);
    l_min tp_mag;
    l_mod tp_mag;
    l_msg tp_mag;
    l_key_parameters tp_key_parameters;
  begin
    if src is null
    then
      raise_application_error( -20010, 'No input buffer provided.' );
    elsif prv_key is null
    then
      raise_application_error( -20011, 'no key provided' );
    elsif pubkey_alg is null
    then
      raise_application_error( -20012, 'PL/SQL function returned an error.' );
    elsif pubkey_alg not in ( KEY_TYPE_RSA, KEY_TYPE_EC, KEY_TYPE_EdDSA )
    then
      raise_application_error( -20013, 'invalid cipher type passed' );
    elsif sign_alg is null
    then
      raise_application_error( -20014, 'PL/SQL function returned an error.' );
    end if;
    return case pubkey_alg
             when KEY_TYPE_RSA then
               sign_rsa( src, prv_key, pubkey_alg, sign_alg )
             when KEY_TYPE_EC then
               sign_ec( src, prv_key, pubkey_alg, sign_alg )
             when KEY_TYPE_EdDSA then
               sign_eddsa( src, prv_key, pubkey_alg, sign_alg )
           end;
  end;
  --
  function verify_rsa( src raw
                     , sign raw
                     , pub_key raw
                     , pubkey_alg binary_integer
                     , sign_alg binary_integer
                     )
  return boolean
  is
    l_mod tp_mag;
    l_padded tp_mag;
    l_tmp raw(1);
    l_decr raw(3999);
    l_idx pls_integer;
    l_hash_type pls_integer;
    l_key_parameters tp_key_parameters;
    l_trailer raw(2);
    l_rv boolean;
  begin
    if pubkey_alg != KEY_TYPE_RSA
    then
      return false;
    end if;
    if sign_alg not in ( SIGN_SHA224_RSA
                       , SIGN_SHA256_RSA
                       , SIGN_SHA256_RSA_X931
                       , SIGN_SHA384_RSA
                       , SIGN_SHA384_RSA_X931
                       , SIGN_SHA512_RSA
                       , SIGN_SHA512_RSA_X931
                       , SIGN_SHA1_RSA
                       , SIGN_SHA1_RSA_X931
                       , SIGN_MD2_RSA
                       , SIGN_MD5_RSA
                       , SIGN_SHA256_RSA_PSS
                       )
    then
      raise_application_error( -20016, 'invalid cipher type passed' );
    elsif not parse_DER_RSA_PUB_key( base64_decode( pub_key ), l_key_parameters )
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    l_mod := mag( l_key_parameters(1) );
    l_padded := powmod( mag( sign ), mag( l_key_parameters(2) ), l_mod );
    if sign_alg in ( SIGN_SHA256_RSA_X931
                   , SIGN_SHA384_RSA_X931
                   , SIGN_SHA512_RSA_X931
                   , SIGN_SHA1_RSA_X931
                   )
    then
      if bitand( l_padded(0), 15 ) != 12
      then
        l_padded := rsub( l_mod, l_padded );
      end if;
      if bitand( l_padded(0), 15 ) != 12
      then
        return false;
      end if;
      l_decr := demag( l_padded );
      if utl_raw.substr( l_decr, 1, 2 ) != hextoraw( '6BBB' )
      then
        return false;
      end if;
      -- remove X9.31 padding
      for i in 3 .. utl_raw.length( l_decr )
      loop
        l_idx := i;
        l_tmp := utl_raw.substr( l_decr, i, 1 );
        exit when l_tmp = 'BA';
        if l_tmp != hextoraw( 'BB' )
        then
          return false;
        end if;
      end loop;
      l_decr := utl_raw.substr( l_decr, l_idx + 1 );
      l_trailer := utl_raw.substr( l_decr, -2 );
      l_hash_type := case sign_alg
                       when SIGN_SHA1_RSA_X931   then HASH_SH1
                       when SIGN_SHA256_RSA_X931 then HASH_SH256
                       when SIGN_SHA512_RSA_X931 then HASH_SH512
                       when SIGN_SHA384_RSA_X931 then HASH_SH384
                     end;
      l_rv := (  ( sign_alg = SIGN_SHA1_RSA_X931 and l_trailer = c_X931_TRAILER_SH1 )
              or ( sign_alg = SIGN_SHA512_RSA_X931 and l_trailer = c_X931_TRAILER_SH512 )
              or ( sign_alg = SIGN_SHA256_RSA_X931 and l_trailer = c_X931_TRAILER_SH256 )
              or ( sign_alg = SIGN_SHA384_RSA_X931 and l_trailer = c_X931_TRAILER_SH384 )
              ) and utl_raw.substr( l_decr, 1, utl_raw.length( l_decr ) - 2 ) = hash( src, l_hash_type );
    elsif sign_alg in ( SIGN_SHA256_RSA_PSS
                      , SIGN_SHA384_RSA_PSS
                      , SIGN_SHA512_RSA_PSS
                      )
    then
      l_decr := demag( l_padded );
      if utl_raw.substr( l_decr, -1 ) != hextoraw( 'BC' )
      then
        return false;
      end if;
      declare
        l_h raw(3999);
        l_mh raw(3999);
        l_db raw(3999);
        l_masked raw(3999);
        l_salt raw(3999);
        l_hlen pls_integer;
        l_sz pls_integer;
      begin
        l_hash_type := case sign_alg
                         when SIGN_SHA256_RSA_PSS then HASH_SH256
                         when SIGN_SHA512_RSA_PSS then HASH_SH512
                         when SIGN_SHA384_RSA_PSS then HASH_SH384
                       end;
        l_hlen := case sign_alg
                    when SIGN_SHA256_RSA_PSS then 32
                    when SIGN_SHA512_RSA_PSS then 64
                    when SIGN_SHA384_RSA_PSS then 48
                  end;
        l_key_parameters(1) := demag( l_mod ); -- get rid of any leading 00
        l_mh := hash( src, l_hash_type );
        l_sz := utl_raw.length( l_key_parameters(1) );
        if utl_raw.length( l_decr ) < l_sz
        then
          l_decr := utl_raw.concat( utl_raw.copies( '00', l_sz - utl_raw.length( l_decr ) ), l_decr );
        end if;
        l_h := utl_raw.substr( l_decr, - l_hlen - 1, l_hlen );
        l_masked := utl_raw.substr( l_decr, 1, utl_raw.length( l_decr ) - l_hlen - 1 );
        l_db := utl_raw.bit_xor( l_masked
                               , mgf1( l_h, utl_raw.length( l_masked ), l_hash_type )
                               );
        l_db := utl_raw.bit_and( l_db, get_rsa_pss_mask( l_key_parameters(1) ) );
        if substr( ltrim( l_db, '0' ), 1, 1 ) != '1'
        then
          return false;
        end if;
        l_idx := instr( l_db, '1' );
        if mod( l_idx, 2 ) = 1
        then
          return false;
        end if;
        l_salt := substr( l_db, l_idx + 1 );
        return hash( utl_raw.concat( utl_raw.copies( '00', 8 ), l_mh, l_salt )
                   , l_hash_type ) = l_h;
      end;
    else
      l_decr := demag( l_padded );
      if utl_raw.substr( l_decr, 1, 2 ) != hextoraw( '01FF' )
      then
        return false;
      end if;
      -- remove EMSA-PKCS1-v1_5 padding
      for i in 3 .. utl_raw.length( l_decr )
      loop
        l_idx := i;
        l_tmp := utl_raw.substr( l_decr, i, 1 );
        exit when l_tmp = '00';
        if l_tmp != hextoraw( 'FF' )
        then
          return false;
        end if;
      end loop;
      l_decr := utl_raw.substr( l_decr, l_idx + 1 );
      if sign_alg = SIGN_SHA1_RSA
      then
        l_hash_type := HASH_SH1;
        l_idx := utl_raw.length( c_ASN1_SH1 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_SH1;
      elsif sign_alg = SIGN_SHA512_RSA
      then
        l_hash_type := HASH_SH512;
        l_idx := utl_raw.length( c_ASN1_SH512 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_SH512;
      elsif sign_alg = SIGN_SHA256_RSA
      then
        l_hash_type := HASH_SH256;
        l_idx := utl_raw.length( c_ASN1_SH256 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_SH256;
      elsif sign_alg = SIGN_SHA384_RSA
      then
        l_hash_type := HASH_SH384;
        l_idx := utl_raw.length( c_ASN1_SH384 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_SH384;
      elsif sign_alg = SIGN_SHA224_RSA
      then
        l_hash_type := HASH_SH224;
        l_idx := utl_raw.length( c_ASN1_SH224 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_SH224;
      elsif sign_alg = SIGN_MD2_RSA
      then
        l_hash_type := HASH_MD2;
        l_idx := utl_raw.length( c_ASN1_MD2 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_MD2;
      elsif sign_alg = SIGN_MD5_RSA
      then
        l_hash_type := HASH_MD5;
        l_idx := utl_raw.length( c_ASN1_MD5 );
        l_rv := utl_raw.substr( l_decr, 1, l_idx ) = c_ASN1_MD5;
      end if;
      l_rv := l_rv and l_idx > 10 and utl_raw.substr( l_decr, l_idx + 1 ) = hash( src, l_hash_type );
    end if;
    return l_rv;
  end;
  --
  function verify_ec( src raw
                    , sign raw
                    , pub_key raw
                    , pubkey_alg binary_integer
                    , sign_alg binary_integer
                    )
  return boolean
  is
    l_hash_type pls_integer;
    l_curve tp_ec_curve;
    l_inv tp_mag;
    l_u1 tp_mag;
    l_u2 tp_mag;
    l_r raw(32767);
    l_s raw(32767);
    l_w tp_ec_point;
    l_verify tp_ec_point;
    l_key_parameters tp_key_parameters;
    l_ind pls_integer;
  begin
    if pubkey_alg != KEY_TYPE_EC
    then
      return false;
    end if;
    if sign_alg not in ( SIGN_SHA256withECDSA
                       , SIGN_SHA384withECDSA
                       , SIGN_SHA512withECDSA
                       , SIGN_SHA256withECDSAinP1363
                       , SIGN_SHA384withECDSAinP1363
                       , SIGN_SHA512withECDSAinP1363
                       )
    then
      raise_application_error( -20016, 'invalid cipher type passed' );
    elsif not parse_DER_EC_PUB_key( base64_decode( pub_key ), l_key_parameters )
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    get_named_curve( utl_raw.cast_to_varchar2( l_key_parameters(1) ), l_curve );
    l_hash_type := case sign_alg
                     when SIGN_SHA256withECDSA then HASH_SH256
                     when SIGN_SHA384withECDSA then HASH_SH384
                     when SIGN_SHA512withECDSA then HASH_SH512
                     when SIGN_SHA256withECDSAinP1363 then HASH_SH256
                     when SIGN_SHA384withECDSAinP1363 then HASH_SH384
                     when SIGN_SHA512withECDSAinP1363 then HASH_SH512
                   end;
    bytes_to_ec_point( l_key_parameters(2), l_curve, l_w );
    if sign_alg in ( SIGN_SHA256withECDSA
                   , SIGN_SHA384withECDSA
                   , SIGN_SHA512withECDSA
                   )
    then
      check_starting_sequence( sign, l_ind );
      l_r := get_integer( sign, l_ind );
      l_s := get_integer( sign, l_ind );
    else
      l_r := utl_raw.substr( sign, 1, l_curve.nlen );
      l_s := utl_raw.substr( sign, l_curve.nlen + 1 );
    end if;
    if ltrim( rawtohex( l_r ), '0' ) is null or ltrim( rawtohex( l_s ), '0' ) is null
    then
      return false;
    end if;
    l_inv := powmod( mag( l_s ), nsub( l_curve.group_order, 2 ), l_curve.group_order );
    l_u1 := mulmod( mag( hash( src, l_hash_type ) ), l_inv, l_curve.group_order );
    l_u2 := mulmod( mag( l_r ), l_inv, l_curve.group_order );
    l_verify := add_point( multiply_point( l_curve.generator, l_u1, l_curve )
                         , multiply_point( l_w, l_u2, l_curve )
                         , l_curve
                         );
    return utl_raw.compare( demag( l_verify.x ), ltrim( l_r, '0' ) ) = 0;
  end;
  --
  function verify_eddsa( src raw
                       , sign raw
                       , pub_key raw
                       , pubkey_alg binary_integer
                       , sign_alg binary_integer
                       )
  return boolean
  is
    l_hash_type pls_integer;
    l_curve tp_ed_curve;
    l_tst tp_ed_point;
    l_inv tp_mag;
    l_chk tp_mag;
    l_k   tp_mag;
    l_tmp raw(3999);
    l_chk_val raw(3999);
    l_key_parameters tp_key_parameters;
  begin
    if pubkey_alg != KEY_TYPE_EdDSA
    then
      return false;
    end if;
    if sign_alg not in ( SIGN_Ed25519 )
    then
      raise_application_error( -20016, 'invalid cipher type passed' );
    elsif not parse_DER_EDDSA_PUB_key( base64_decode( pub_key ), l_key_parameters )
    then
      raise_application_error( -20017, 'PL/SQL function returned an error.' );
    end if;
    get_named_ed_curve( utl_raw.cast_to_varchar2( l_key_parameters(1) ), l_curve );
    if 2 * l_curve.nlen != utl_raw.length( sign )
    then
      raise value_error;
    elsif l_curve.nlen != utl_raw.length( l_key_parameters(2) )
    then
      raise value_error;
    end if;
    l_hash_type := HASH_SH512;
    l_tmp := hash( utl_raw.concat( utl_raw.substr( sign, 1, l_curve.nlen )
                                 , l_key_parameters(2)
                                 , src
                                 )
                 , l_hash_type
                 );
    l_k := xmod( mag( utl_raw.reverse( l_tmp ) ), l_curve.l );
    l_tst := ed_add( ed_scalarmultiply( l_curve.b, l_curve, mag( utl_raw.reverse( utl_raw.substr( sign, - l_curve.nlen ) ) ) )
                   , ed_scalarmultiply( negate_ed_point( l_key_parameters(2), l_curve ), l_curve, l_k )
                   , l_curve
                   );
    l_inv := powmod( l_tst.z, nsub( l_curve.q, 2 ), l_curve.q );
    l_chk := mulmod( l_tst.y, l_inv, l_curve.q );
    l_chk_val := substr( lpad( demag( l_chk ), l_curve.nlen * 2, '0' ), - l_curve.nlen * 2 );
    if bitand( mulmod( l_tst.x, l_inv, l_curve.q )(0), 1 ) = 1
    then
      l_chk_val := utl_raw.bit_or( '80', l_chk_val );
    end if;
    l_chk_val := utl_raw.reverse( l_chk_val );
    return utl_raw.compare( l_chk_val ,utl_raw.substr( sign, 1, l_curve.nlen ) ) = 0;
  end;
  --
  function verify( src raw
                 , sign raw
                 , pub_key raw
                 , pubkey_alg binary_integer
                 , sign_alg binary_integer
                 )
  return boolean
  is
  begin
    if src is null
    then
      raise_application_error( -20010, 'No input buffer provided.' );
    elsif sign is null
    then
      raise_application_error( -20011, 'invalid encryption/decryption/signature state passed' );
    elsif pub_key is null
    then
      raise_application_error( -20012, 'no key provided' );
    elsif pubkey_alg is null
    then
      raise_application_error( -20013, 'PL/SQL function returned an error.' );
    elsif pubkey_alg not in ( KEY_TYPE_RSA, KEY_TYPE_EC, KEY_TYPE_EdDSA )
    then
      raise_application_error( -20014, 'invalid cipher type passed' );
    elsif sign_alg is null
    then
      raise_application_error( -20015, 'PL/SQL function returned an error.' );
    end if;
    return verify_rsa( src, sign, pub_key, pubkey_alg, sign_alg )
        or verify_ec( src, sign, pub_key, pubkey_alg, sign_alg )
        or verify_eddsa( src, sign, pub_key, pubkey_alg, sign_alg );
  end;
  --
end;
/
