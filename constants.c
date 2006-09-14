/* xsub automagically generated constant evaluator function */

static double
constant(char* name)
{
    errno = 0;
    switch (*name) {
    case 'A':
	if (strEQ(name, "AT_MD5_WITH_RSA_ENCRYPTION"))
#ifdef SSL_AT_MD5_WITH_RSA_ENCRYPTION
	    return SSL_AT_MD5_WITH_RSA_ENCRYPTION;
#else
	    goto not_there;
#endif
	break;
    case 'B':
	break;
    case 'C':
	if (strEQ(name, "CB_ACCEPT_EXIT"))
#ifdef SSL_CB_ACCEPT_EXIT
	    return SSL_CB_ACCEPT_EXIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CB_ACCEPT_LOOP"))
#ifdef SSL_CB_ACCEPT_LOOP
	    return SSL_CB_ACCEPT_LOOP;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CB_CONNECT_EXIT"))
#ifdef SSL_CB_CONNECT_EXIT
	    return SSL_CB_CONNECT_EXIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CB_CONNECT_LOOP"))
#ifdef SSL_CB_CONNECT_LOOP
	    return SSL_CB_CONNECT_LOOP;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_DES_192_EDE3_CBC_WITH_MD5"))
#ifdef SSL_CK_DES_192_EDE3_CBC_WITH_MD5
	    return SSL_CK_DES_192_EDE3_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_DES_192_EDE3_CBC_WITH_SHA"))
#ifdef SSL_CK_DES_192_EDE3_CBC_WITH_SHA
	    return SSL_CK_DES_192_EDE3_CBC_WITH_SHA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_DES_64_CBC_WITH_MD5"))
#ifdef SSL_CK_DES_64_CBC_WITH_MD5
	    return SSL_CK_DES_64_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_DES_64_CBC_WITH_SHA"))
#ifdef SSL_CK_DES_64_CBC_WITH_SHA
	    return SSL_CK_DES_64_CBC_WITH_SHA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_DES_64_CFB64_WITH_MD5_1"))
#ifdef SSL_CK_DES_64_CFB64_WITH_MD5_1
	    return SSL_CK_DES_64_CFB64_WITH_MD5_1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_IDEA_128_CBC_WITH_MD5"))
#ifdef SSL_CK_IDEA_128_CBC_WITH_MD5
	    return SSL_CK_IDEA_128_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_NULL"))
#ifdef SSL_CK_NULL
	    return SSL_CK_NULL;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_NULL_WITH_MD5"))
#ifdef SSL_CK_NULL_WITH_MD5
	    return SSL_CK_NULL_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_RC2_128_CBC_EXPORT40_WITH_MD5"))
#ifdef SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5
	    return SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_RC2_128_CBC_WITH_MD5"))
#ifdef SSL_CK_RC2_128_CBC_WITH_MD5
	    return SSL_CK_RC2_128_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_RC4_128_EXPORT40_WITH_MD5"))
#ifdef SSL_CK_RC4_128_EXPORT40_WITH_MD5
	    return SSL_CK_RC4_128_EXPORT40_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CK_RC4_128_WITH_MD5"))
#ifdef SSL_CK_RC4_128_WITH_MD5
	    return SSL_CK_RC4_128_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CLIENT_VERSION"))
#ifdef SSL_CLIENT_VERSION
	    return SSL_CLIENT_VERSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "CT_X509_CERTIFICATE"))
#ifdef SSL_CT_X509_CERTIFICATE
	    return SSL_CT_X509_CERTIFICATE;
#else
	    goto not_there;
#endif
	break;
    case 'D':
	break;
    case 'E':
      if (strEQ(name, "ERROR_NONE"))
#ifdef SSL_ERROR_NONE
      return SSL_ERROR_NONE;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_SSL"))
#ifdef SSL_ERROR_SSL
      return SSL_ERROR_SSL;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_SYSCALL"))
#ifdef SSL_ERROR_SYSCALL
      return SSL_ERROR_SYSCALL;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_WANT_CONNECT"))
#ifdef SSL_ERROR_WANT_CONNECT
      return SSL_ERROR_WANT_CONNECT;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_WANT_READ"))
#ifdef SSL_ERROR_WANT_READ
      return SSL_ERROR_WANT_READ;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_WANT_WRITE"))
#ifdef SSL_ERROR_WANT_WRITE
      return SSL_ERROR_WANT_WRITE;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_WANT_X509_LOOKUP"))
#ifdef SSL_ERROR_WANT_X509_LOOKUP
      return SSL_ERROR_WANT_X509_LOOKUP;
#else
      goto not_there;
#endif
      if (strEQ(name, "ERROR_ZERO_RETURN"))
#ifdef SSL_ERROR_ZERO_RETURN
      return SSL_ERROR_ZERO_RETURN;
#else
      goto not_there;
#endif
      break;
    case 'F':
	if (strEQ(name, "FILETYPE_ASN1"))
#ifdef SSL_FILETYPE_ASN1
	    return SSL_FILETYPE_ASN1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "FILETYPE_PEM"))
#ifdef SSL_FILETYPE_PEM
	    return SSL_FILETYPE_PEM;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_CLIENT_CERTIFICATE"))
#ifdef SSL_F_CLIENT_CERTIFICATE
	    return SSL_F_CLIENT_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_CLIENT_HELLO"))
#ifdef SSL_F_CLIENT_HELLO
	    return SSL_F_CLIENT_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_CLIENT_MASTER_KEY"))
#ifdef SSL_F_CLIENT_MASTER_KEY
	    return SSL_F_CLIENT_MASTER_KEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_D2I_SSL_SESSION"))
#ifdef SSL_F_D2I_SSL_SESSION
	    return SSL_F_D2I_SSL_SESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_CLIENT_FINISHED"))
#ifdef SSL_F_GET_CLIENT_FINISHED
	    return SSL_F_GET_CLIENT_FINISHED;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_CLIENT_HELLO"))
#ifdef SSL_F_GET_CLIENT_HELLO
	    return SSL_F_GET_CLIENT_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_CLIENT_MASTER_KEY"))
#ifdef SSL_F_GET_CLIENT_MASTER_KEY
	    return SSL_F_GET_CLIENT_MASTER_KEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_SERVER_FINISHED"))
#ifdef SSL_F_GET_SERVER_FINISHED
	    return SSL_F_GET_SERVER_FINISHED;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_SERVER_HELLO"))
#ifdef SSL_F_GET_SERVER_HELLO
	    return SSL_F_GET_SERVER_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_GET_SERVER_VERIFY"))
#ifdef SSL_F_GET_SERVER_VERIFY
	    return SSL_F_GET_SERVER_VERIFY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_I2D_SSL_SESSION"))
#ifdef SSL_F_I2D_SSL_SESSION
	    return SSL_F_I2D_SSL_SESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_READ_N"))
#ifdef SSL_F_READ_N
	    return SSL_F_READ_N;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_REQUEST_CERTIFICATE"))
#ifdef SSL_F_REQUEST_CERTIFICATE
	    return SSL_F_REQUEST_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SERVER_HELLO"))
#ifdef SSL_F_SERVER_HELLO
	    return SSL_F_SERVER_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ACCEPT"))
#ifdef SSL_F_SSL_ACCEPT
	    return SSL_F_SSL_ACCEPT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_CERT_NEW"))
#ifdef SSL_F_SSL_CERT_NEW
	    return SSL_F_SSL_CERT_NEW;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_CONNECT"))
#ifdef SSL_F_SSL_CONNECT
	    return SSL_F_SSL_CONNECT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_DES_CBC_INIT"))
#ifdef SSL_F_SSL_ENC_DES_CBC_INIT
	    return SSL_F_SSL_ENC_DES_CBC_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_DES_CFB_INIT"))
#ifdef SSL_F_SSL_ENC_DES_CFB_INIT
	    return SSL_F_SSL_ENC_DES_CFB_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_DES_EDE3_CBC_INIT"))
#ifdef SSL_F_SSL_ENC_DES_EDE3_CBC_INIT
	    return SSL_F_SSL_ENC_DES_EDE3_CBC_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_IDEA_CBC_INIT"))
#ifdef SSL_F_SSL_ENC_IDEA_CBC_INIT
	    return SSL_F_SSL_ENC_IDEA_CBC_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_NULL_INIT"))
#ifdef SSL_F_SSL_ENC_NULL_INIT
	    return SSL_F_SSL_ENC_NULL_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_RC2_CBC_INIT"))
#ifdef SSL_F_SSL_ENC_RC2_CBC_INIT
	    return SSL_F_SSL_ENC_RC2_CBC_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_ENC_RC4_INIT"))
#ifdef SSL_F_SSL_ENC_RC4_INIT
	    return SSL_F_SSL_ENC_RC4_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_GET_NEW_SESSION"))
#ifdef SSL_F_SSL_GET_NEW_SESSION
	    return SSL_F_SSL_GET_NEW_SESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_MAKE_CIPHER_LIST"))
#ifdef SSL_F_SSL_MAKE_CIPHER_LIST
	    return SSL_F_SSL_MAKE_CIPHER_LIST;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_NEW"))
#ifdef SSL_F_SSL_NEW
	    return SSL_F_SSL_NEW;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_READ"))
#ifdef SSL_F_SSL_READ
	    return SSL_F_SSL_READ;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_RSA_PRIVATE_DECRYPT"))
#ifdef SSL_F_SSL_RSA_PRIVATE_DECRYPT
	    return SSL_F_SSL_RSA_PRIVATE_DECRYPT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_RSA_PUBLIC_ENCRYPT"))
#ifdef SSL_F_SSL_RSA_PUBLIC_ENCRYPT
	    return SSL_F_SSL_RSA_PUBLIC_ENCRYPT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SESSION_NEW"))
#ifdef SSL_F_SSL_SESSION_NEW
	    return SSL_F_SSL_SESSION_NEW;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SESSION_PRINT_FP"))
#ifdef SSL_F_SSL_SESSION_PRINT_FP
	    return SSL_F_SSL_SESSION_PRINT_FP;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SET_CERTIFICATE"))
#ifdef SSL_F_SSL_SET_CERTIFICATE
	    return SSL_F_SSL_SET_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SET_FD"))
#ifdef SSL_F_SSL_SET_FD
	    return SSL_F_SSL_SET_FD;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SET_RFD"))
#ifdef SSL_F_SSL_SET_RFD
	    return SSL_F_SSL_SET_RFD;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_SET_WFD"))
#ifdef SSL_F_SSL_SET_WFD
	    return SSL_F_SSL_SET_WFD;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_STARTUP"))
#ifdef SSL_F_SSL_STARTUP
	    return SSL_F_SSL_STARTUP;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_CERTIFICATE"))
#ifdef SSL_F_SSL_USE_CERTIFICATE
	    return SSL_F_SSL_USE_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_CERTIFICATE_ASN1"))
#ifdef SSL_F_SSL_USE_CERTIFICATE_ASN1
	    return SSL_F_SSL_USE_CERTIFICATE_ASN1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_CERTIFICATE_FILE"))
#ifdef SSL_F_SSL_USE_CERTIFICATE_FILE
	    return SSL_F_SSL_USE_CERTIFICATE_FILE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_PRIVATEKEY"))
#ifdef SSL_F_SSL_USE_PRIVATEKEY
	    return SSL_F_SSL_USE_PRIVATEKEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_PRIVATEKEY_ASN1"))
#ifdef SSL_F_SSL_USE_PRIVATEKEY_ASN1
	    return SSL_F_SSL_USE_PRIVATEKEY_ASN1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_PRIVATEKEY_FILE"))
#ifdef SSL_F_SSL_USE_PRIVATEKEY_FILE
	    return SSL_F_SSL_USE_PRIVATEKEY_FILE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_RSAPRIVATEKEY"))
#ifdef SSL_F_SSL_USE_RSAPRIVATEKEY
	    return SSL_F_SSL_USE_RSAPRIVATEKEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_RSAPRIVATEKEY_ASN1"))
#ifdef SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1
	    return SSL_F_SSL_USE_RSAPRIVATEKEY_ASN1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_SSL_USE_RSAPRIVATEKEY_FILE"))
#ifdef SSL_F_SSL_USE_RSAPRIVATEKEY_FILE
	    return SSL_F_SSL_USE_RSAPRIVATEKEY_FILE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "F_WRITE_PENDING"))
#ifdef SSL_F_WRITE_PENDING
	    return SSL_F_WRITE_PENDING;
#else
	    goto not_there;
#endif
	break;
    case 'G':
	break;
    case 'H':
	break;
    case 'I':
	break;
    case 'J':
	break;
    case 'K':
	break;
    case 'L':
	break;
    case 'M':
	if (strEQ(name, "MAX_MASTER_KEY_LENGTH_IN_BITS"))
#ifdef SSL_MAX_MASTER_KEY_LENGTH_IN_BITS
	    return SSL_MAX_MASTER_KEY_LENGTH_IN_BITS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MAX_RECORD_LENGTH_2_BYTE_HEADER"))
#ifdef SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER
	    return SSL_MAX_RECORD_LENGTH_2_BYTE_HEADER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MAX_RECORD_LENGTH_3_BYTE_HEADER"))
#ifdef SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER
	    return SSL_MAX_RECORD_LENGTH_3_BYTE_HEADER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MAX_SSL_SESSION_ID_LENGTH_IN_BYTES"))
#ifdef SSL_MAX_SSL_SESSION_ID_LENGTH_IN_BYTES
	    return SSL_MAX_SSL_SESSION_ID_LENGTH_IN_BYTES;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MIN_RSA_MODULUS_LENGTH_IN_BYTES"))
#ifdef SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES
	    return SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_CLIENT_CERTIFICATE"))
#ifdef SSL_MT_CLIENT_CERTIFICATE
	    return SSL_MT_CLIENT_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_CLIENT_FINISHED"))
#ifdef SSL_MT_CLIENT_FINISHED
	    return SSL_MT_CLIENT_FINISHED;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_CLIENT_HELLO"))
#ifdef SSL_MT_CLIENT_HELLO
	    return SSL_MT_CLIENT_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_CLIENT_MASTER_KEY"))
#ifdef SSL_MT_CLIENT_MASTER_KEY
	    return SSL_MT_CLIENT_MASTER_KEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_ERROR"))
#ifdef SSL_MT_ERROR
	    return SSL_MT_ERROR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_REQUEST_CERTIFICATE"))
#ifdef SSL_MT_REQUEST_CERTIFICATE
	    return SSL_MT_REQUEST_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_SERVER_FINISHED"))
#ifdef SSL_MT_SERVER_FINISHED
	    return SSL_MT_SERVER_FINISHED;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_SERVER_HELLO"))
#ifdef SSL_MT_SERVER_HELLO
	    return SSL_MT_SERVER_HELLO;
#else
	    goto not_there;
#endif
	if (strEQ(name, "MT_SERVER_VERIFY"))
#ifdef SSL_MT_SERVER_VERIFY
	    return SSL_MT_SERVER_VERIFY;
#else
	    goto not_there;
#endif
	break;
    case 'N':
	if (strEQ(name, "NOTHING"))
#ifdef SSL_NOTHING
	    return SSL_NOTHING;
#else
	    goto not_there;
#endif
	break;
    case 'O':
	if (strEQ(name, "OPENSSL_VERSION_NUMBER"))
#ifdef OPENSSL_VERSION_NUMBER
            return OPENSSL_VERSION_NUMBER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_MICROSOFT_SESS_ID_BUG"))
#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
	    return SSL_OP_MICROSOFT_SESS_ID_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_CHALLENGE_BUG"))
#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
	    return SSL_OP_NETSCAPE_CHALLENGE_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG"))
#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
	    return SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_SSLREF2_REUSE_CERT_TYPE_BUG"))
#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
	    return SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_MICROSOFT_BIG_SSLV3_BUFFER"))
#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
	    return SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_MSIE_SSLV2_RSA_PADDING"))
#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
	    return SSL_OP_MSIE_SSLV2_RSA_PADDING;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_SSLEAY_080_CLIENT_DH_BUG"))
#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
	    return SSL_OP_SSLEAY_080_CLIENT_DH_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_TLS_D5_BUG"))
#ifdef SSL_OP_TLS_D5_BUG
	    return SSL_OP_TLS_D5_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_SINGLE_DH_USE"))
#ifdef SSL_OP_SINGLE_DH_USE
	    return SSL_OP_SINGLE_DH_USE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_EPHEMERAL_RSA"))
#ifdef SSL_OP_EPHEMERAL_RSA
	    return SSL_OP_EPHEMERAL_RSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_CA_DN_BUG"))
#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
	    return SSL_OP_NETSCAPE_CA_DN_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NON_EXPORT_FIRST"))
#ifdef SSL_OP_NON_EXPORT_FIRST
	    return SSL_OP_NON_EXPORT_FIRST;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG"))
#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
	    return SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_SSLv2"))
#ifdef SSL_OP_NO_SSLv2
	    return SSL_OP_NO_SSLv2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_SSLv3"))
#ifdef SSL_OP_NO_SSLv3
	    return SSL_OP_NO_SSLv3;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_TLSv1"))
#ifdef SSL_OP_NO_TLSv1
	    return SSL_OP_NO_TLSv1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_ALL"))
#ifdef SSL_OP_ALL
	    return SSL_OP_ALL;
#else
	    goto not_there;
#endif

    case 'P':
	if (strEQ(name, "PE_BAD_CERTIFICATE"))
#ifdef SSL_PE_BAD_CERTIFICATE
	    return SSL_PE_BAD_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "PE_NO_CERTIFICATE"))
#ifdef SSL_PE_NO_CERTIFICATE
	    return SSL_PE_NO_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "PE_NO_CIPHER"))
#ifdef SSL_PE_NO_CIPHER
	    return SSL_PE_NO_CIPHER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "PE_UNSUPPORTED_CERTIFICATE_TYPE"))
#ifdef SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE
	    return SSL_PE_UNSUPPORTED_CERTIFICATE_TYPE;
#else
	    goto not_there;
#endif
	break;
    case 'Q':
	break;
    case 'R':
	if (strEQ(name, "READING"))
#ifdef SSL_READING
	    return SSL_READING;
#else
	    goto not_there;
#endif
	if (strEQ(name, "RWERR_BAD_MAC_DECODE"))
#ifdef SSL_RWERR_BAD_MAC_DECODE
	    return SSL_RWERR_BAD_MAC_DECODE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "RWERR_BAD_WRITE_RETRY"))
#ifdef SSL_RWERR_BAD_WRITE_RETRY
	    return SSL_RWERR_BAD_WRITE_RETRY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "RWERR_INTERNAL_ERROR"))
#ifdef SSL_RWERR_INTERNAL_ERROR
	    return SSL_RWERR_INTERNAL_ERROR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_AUTHENTICATION_TYPE"))
#ifdef SSL_R_BAD_AUTHENTICATION_TYPE
	    return SSL_R_BAD_AUTHENTICATION_TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_CHECKSUM"))
#ifdef SSL_R_BAD_CHECKSUM
	    return SSL_R_BAD_CHECKSUM;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_MAC_DECODE"))
#ifdef SSL_R_BAD_MAC_DECODE
	    return SSL_R_BAD_MAC_DECODE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_RESPONSE_ARGUMENT"))
#ifdef SSL_R_BAD_RESPONSE_ARGUMENT
	    return SSL_R_BAD_RESPONSE_ARGUMENT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_SSL_FILETYPE"))
#ifdef SSL_R_BAD_SSL_FILETYPE
	    return SSL_R_BAD_SSL_FILETYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_SSL_SESSION_ID_LENGTH"))
#ifdef SSL_R_BAD_SSL_SESSION_ID_LENGTH
	    return SSL_R_BAD_SSL_SESSION_ID_LENGTH;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_STATE"))
#ifdef SSL_R_BAD_STATE
	    return SSL_R_BAD_STATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_BAD_WRITE_RETRY"))
#ifdef SSL_R_BAD_WRITE_RETRY
	    return SSL_R_BAD_WRITE_RETRY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_CHALLENGE_IS_DIFFERENT"))
#ifdef SSL_R_CHALLENGE_IS_DIFFERENT
	    return SSL_R_CHALLENGE_IS_DIFFERENT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_CIPHER_CODE_TOO_LONG"))
#ifdef SSL_R_CIPHER_CODE_TOO_LONG
	    return SSL_R_CIPHER_CODE_TOO_LONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_CIPHER_TABLE_SRC_ERROR"))
#ifdef SSL_R_CIPHER_TABLE_SRC_ERROR
	    return SSL_R_CIPHER_TABLE_SRC_ERROR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_CONECTION_ID_IS_DIFFERENT"))
#ifdef SSL_R_CONECTION_ID_IS_DIFFERENT
	    return SSL_R_CONECTION_ID_IS_DIFFERENT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_INVALID_CHALLENGE_LENGTH"))
#ifdef SSL_R_INVALID_CHALLENGE_LENGTH
	    return SSL_R_INVALID_CHALLENGE_LENGTH;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_CERTIFICATE_SET"))
#ifdef SSL_R_NO_CERTIFICATE_SET
	    return SSL_R_NO_CERTIFICATE_SET;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_CERTIFICATE_SPECIFIED"))
#ifdef SSL_R_NO_CERTIFICATE_SPECIFIED
	    return SSL_R_NO_CERTIFICATE_SPECIFIED;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_CIPHER_LIST"))
#ifdef SSL_R_NO_CIPHER_LIST
	    return SSL_R_NO_CIPHER_LIST;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_CIPHER_MATCH"))
#ifdef SSL_R_NO_CIPHER_MATCH
	    return SSL_R_NO_CIPHER_MATCH;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_CIPHER_WE_TRUST"))
#ifdef SSL_R_NO_CIPHER_WE_TRUST
	    return SSL_R_NO_CIPHER_WE_TRUST;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_PRIVATEKEY"))
#ifdef SSL_R_NO_PRIVATEKEY
	    return SSL_R_NO_PRIVATEKEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_PUBLICKEY"))
#ifdef SSL_R_NO_PUBLICKEY
	    return SSL_R_NO_PUBLICKEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_READ_METHOD_SET"))
#ifdef SSL_R_NO_READ_METHOD_SET
	    return SSL_R_NO_READ_METHOD_SET;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NO_WRITE_METHOD_SET"))
#ifdef SSL_R_NO_WRITE_METHOD_SET
	    return SSL_R_NO_WRITE_METHOD_SET;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_NULL_SSL_CTX"))
#ifdef SSL_R_NULL_SSL_CTX
	    return SSL_R_NULL_SSL_CTX;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PEER_DID_NOT_RETURN_A_CERTIFICATE"))
#ifdef SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE
	    return SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PEER_ERROR"))
#ifdef SSL_R_PEER_ERROR
	    return SSL_R_PEER_ERROR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PEER_ERROR_CERTIFICATE"))
#ifdef SSL_R_PEER_ERROR_CERTIFICATE
	    return SSL_R_PEER_ERROR_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PEER_ERROR_NO_CIPHER"))
#ifdef SSL_R_PEER_ERROR_NO_CIPHER
	    return SSL_R_PEER_ERROR_NO_CIPHER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE"))
#ifdef SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE
	    return SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PERR_ERROR_NO_CERTIFICATE"))
#ifdef SSL_R_PERR_ERROR_NO_CERTIFICATE
	    return SSL_R_PERR_ERROR_NO_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PUBLIC_KEY_ENCRYPT_ERROR"))
#ifdef SSL_R_PUBLIC_KEY_ENCRYPT_ERROR
	    return SSL_R_PUBLIC_KEY_ENCRYPT_ERROR;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PUBLIC_KEY_IS_NOT_RSA"))
#ifdef SSL_R_PUBLIC_KEY_IS_NOT_RSA
	    return SSL_R_PUBLIC_KEY_IS_NOT_RSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_PUBLIC_KEY_NO_RSA"))
#ifdef SSL_R_PUBLIC_KEY_NO_RSA
	    return SSL_R_PUBLIC_KEY_NO_RSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_READ_WRONG_PACKET_TYPE"))
#ifdef SSL_R_READ_WRONG_PACKET_TYPE
	    return SSL_R_READ_WRONG_PACKET_TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_REVERSE_KEY_ARG_LENGTH_IS_WRONG"))
#ifdef SSL_R_REVERSE_KEY_ARG_LENGTH_IS_WRONG
	    return SSL_R_REVERSE_KEY_ARG_LENGTH_IS_WRONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_REVERSE_MASTER_KEY_LENGTH_IS_WRONG"))
#ifdef SSL_R_REVERSE_MASTER_KEY_LENGTH_IS_WRONG
	    return SSL_R_REVERSE_MASTER_KEY_LENGTH_IS_WRONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_REVERSE_SSL_SESSION_ID_LENGTH_IS_WRONG"))
#ifdef SSL_R_REVERSE_SSL_SESSION_ID_LENGTH_IS_WRONG
	    return SSL_R_REVERSE_SSL_SESSION_ID_LENGTH_IS_WRONG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_SHORT_READ"))
#ifdef SSL_R_SHORT_READ
	    return SSL_R_SHORT_READ;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_SSL_SESSION_ID_IS_DIFFERENT"))
#ifdef SSL_R_SSL_SESSION_ID_IS_DIFFERENT
	    return SSL_R_SSL_SESSION_ID_IS_DIFFERENT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_UNABLE_TO_EXTRACT_PUBLIC_KEY"))
#ifdef SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY
	    return SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_UNDEFINED_INIT_STATE"))
#ifdef SSL_R_UNDEFINED_INIT_STATE
	    return SSL_R_UNDEFINED_INIT_STATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_UNKNOWN_REMOTE_ERROR_TYPE"))
#ifdef SSL_R_UNKNOWN_REMOTE_ERROR_TYPE
	    return SSL_R_UNKNOWN_REMOTE_ERROR_TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_UNKNOWN_STATE"))
#ifdef SSL_R_UNKNOWN_STATE
	    return SSL_R_UNKNOWN_STATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_UNSUPORTED_CIPHER"))
#ifdef SSL_R_UNSUPORTED_CIPHER
	    return SSL_R_UNSUPORTED_CIPHER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_WRONG_PUBLIC_KEY_TYPE"))
#ifdef SSL_R_WRONG_PUBLIC_KEY_TYPE
	    return SSL_R_WRONG_PUBLIC_KEY_TYPE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "R_X509_LIB"))
#ifdef SSL_R_X509_LIB
	    return SSL_R_X509_LIB;
#else
	    goto not_there;
#endif
	if (strEQ(name, "RSA_3"))
#ifdef RSA_3
		return RSA_3;
#else
		goto not_there;
#endif
	if (strEQ(name, "RSA_F4"))
#ifdef RSA_F4
		return RSA_F4;
#else
		goto not_there;
#endif
	break;
    case 'S':
	if (strEQ(name, "SERVER_VERSION"))
#ifdef SSL_SERVER_VERSION
	    return SSL_SERVER_VERSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "SESSION_ASN1_VERSION"))
#ifdef SSL_SESSION_ASN1_VERSION
	    return SSL_SESSION_ASN1_VERSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_ACCEPT"))
#ifdef SSL_ST_ACCEPT
	    return SSL_ST_ACCEPT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_BEFORE"))
#ifdef SSL_ST_BEFORE
	    return SSL_ST_BEFORE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_CLIENT_START_ENCRYPTION"))
#ifdef SSL_ST_CLIENT_START_ENCRYPTION
	    return SSL_ST_CLIENT_START_ENCRYPTION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_CONNECT"))
#ifdef SSL_ST_CONNECT
	    return SSL_ST_CONNECT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_FINISHED_A"))
#ifdef SSL_ST_GET_CLIENT_FINISHED_A
	    return SSL_ST_GET_CLIENT_FINISHED_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_FINISHED_B"))
#ifdef SSL_ST_GET_CLIENT_FINISHED_B
	    return SSL_ST_GET_CLIENT_FINISHED_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_HELLO_A"))
#ifdef SSL_ST_GET_CLIENT_HELLO_A
	    return SSL_ST_GET_CLIENT_HELLO_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_HELLO_B"))
#ifdef SSL_ST_GET_CLIENT_HELLO_B
	    return SSL_ST_GET_CLIENT_HELLO_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_MASTER_KEY_A"))
#ifdef SSL_ST_GET_CLIENT_MASTER_KEY_A
	    return SSL_ST_GET_CLIENT_MASTER_KEY_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_CLIENT_MASTER_KEY_B"))
#ifdef SSL_ST_GET_CLIENT_MASTER_KEY_B
	    return SSL_ST_GET_CLIENT_MASTER_KEY_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_FINISHED_A"))
#ifdef SSL_ST_GET_SERVER_FINISHED_A
	    return SSL_ST_GET_SERVER_FINISHED_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_FINISHED_B"))
#ifdef SSL_ST_GET_SERVER_FINISHED_B
	    return SSL_ST_GET_SERVER_FINISHED_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_HELLO_A"))
#ifdef SSL_ST_GET_SERVER_HELLO_A
	    return SSL_ST_GET_SERVER_HELLO_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_HELLO_B"))
#ifdef SSL_ST_GET_SERVER_HELLO_B
	    return SSL_ST_GET_SERVER_HELLO_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_VERIFY_A"))
#ifdef SSL_ST_GET_SERVER_VERIFY_A
	    return SSL_ST_GET_SERVER_VERIFY_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_GET_SERVER_VERIFY_B"))
#ifdef SSL_ST_GET_SERVER_VERIFY_B
	    return SSL_ST_GET_SERVER_VERIFY_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_INIT"))
#ifdef SSL_ST_INIT
	    return SSL_ST_INIT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_OK"))
#ifdef SSL_ST_OK
	    return SSL_ST_OK;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_READ_BODY"))
#ifdef SSL_ST_READ_BODY
	    return SSL_ST_READ_BODY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_READ_HEADER"))
#ifdef SSL_ST_READ_HEADER
	    return SSL_ST_READ_HEADER;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_CERTIFICATE_A"))
#ifdef SSL_ST_SEND_CLIENT_CERTIFICATE_A
	    return SSL_ST_SEND_CLIENT_CERTIFICATE_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_CERTIFICATE_B"))
#ifdef SSL_ST_SEND_CLIENT_CERTIFICATE_B
	    return SSL_ST_SEND_CLIENT_CERTIFICATE_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_CERTIFICATE_C"))
#ifdef SSL_ST_SEND_CLIENT_CERTIFICATE_C
	    return SSL_ST_SEND_CLIENT_CERTIFICATE_C;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_CERTIFICATE_D"))
#ifdef SSL_ST_SEND_CLIENT_CERTIFICATE_D
	    return SSL_ST_SEND_CLIENT_CERTIFICATE_D;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_FINISHED_A"))
#ifdef SSL_ST_SEND_CLIENT_FINISHED_A
	    return SSL_ST_SEND_CLIENT_FINISHED_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_FINISHED_B"))
#ifdef SSL_ST_SEND_CLIENT_FINISHED_B
	    return SSL_ST_SEND_CLIENT_FINISHED_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_HELLO_A"))
#ifdef SSL_ST_SEND_CLIENT_HELLO_A
	    return SSL_ST_SEND_CLIENT_HELLO_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_HELLO_B"))
#ifdef SSL_ST_SEND_CLIENT_HELLO_B
	    return SSL_ST_SEND_CLIENT_HELLO_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_MASTER_KEY_A"))
#ifdef SSL_ST_SEND_CLIENT_MASTER_KEY_A
	    return SSL_ST_SEND_CLIENT_MASTER_KEY_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_CLIENT_MASTER_KEY_B"))
#ifdef SSL_ST_SEND_CLIENT_MASTER_KEY_B
	    return SSL_ST_SEND_CLIENT_MASTER_KEY_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_REQUEST_CERTIFICATE_A"))
#ifdef SSL_ST_SEND_REQUEST_CERTIFICATE_A
	    return SSL_ST_SEND_REQUEST_CERTIFICATE_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_REQUEST_CERTIFICATE_B"))
#ifdef SSL_ST_SEND_REQUEST_CERTIFICATE_B
	    return SSL_ST_SEND_REQUEST_CERTIFICATE_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_REQUEST_CERTIFICATE_C"))
#ifdef SSL_ST_SEND_REQUEST_CERTIFICATE_C
	    return SSL_ST_SEND_REQUEST_CERTIFICATE_C;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_REQUEST_CERTIFICATE_D"))
#ifdef SSL_ST_SEND_REQUEST_CERTIFICATE_D
	    return SSL_ST_SEND_REQUEST_CERTIFICATE_D;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_FINISHED_A"))
#ifdef SSL_ST_SEND_SERVER_FINISHED_A
	    return SSL_ST_SEND_SERVER_FINISHED_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_FINISHED_B"))
#ifdef SSL_ST_SEND_SERVER_FINISHED_B
	    return SSL_ST_SEND_SERVER_FINISHED_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_HELLO_A"))
#ifdef SSL_ST_SEND_SERVER_HELLO_A
	    return SSL_ST_SEND_SERVER_HELLO_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_HELLO_B"))
#ifdef SSL_ST_SEND_SERVER_HELLO_B
	    return SSL_ST_SEND_SERVER_HELLO_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_VERIFY_A"))
#ifdef SSL_ST_SEND_SERVER_VERIFY_A
	    return SSL_ST_SEND_SERVER_VERIFY_A;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SEND_SERVER_VERIFY_B"))
#ifdef SSL_ST_SEND_SERVER_VERIFY_B
	    return SSL_ST_SEND_SERVER_VERIFY_B;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_SERVER_START_ENCRYPTION"))
#ifdef SSL_ST_SERVER_START_ENCRYPTION
	    return SSL_ST_SERVER_START_ENCRYPTION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_X509_GET_CLIENT_CERTIFICATE"))
#ifdef SSL_ST_X509_GET_CLIENT_CERTIFICATE
	    return SSL_ST_X509_GET_CLIENT_CERTIFICATE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "ST_X509_GET_SERVER_CERTIFICATE"))
#ifdef SSL_ST_X509_GET_SERVER_CERTIFICATE
	    return SSL_ST_X509_GET_SERVER_CERTIFICATE;
#else
	    goto not_there;
#endif
	break;
    case 'T':
#if 0
	if (strEQ(name, "TXT_DES_192_EDE3_CBC_WITH_MD5"))
#ifdef SSL_TXT_DES_192_EDE3_CBC_WITH_MD5
	    return SSL_TXT_DES_192_EDE3_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_DES_192_EDE3_CBC_WITH_SHA"))
#ifdef SSL_TXT_DES_192_EDE3_CBC_WITH_SHA
	    return SSL_TXT_DES_192_EDE3_CBC_WITH_SHA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_DES_64_CBC_WITH_MD5"))
#ifdef SSL_TXT_DES_64_CBC_WITH_MD5
	    return SSL_TXT_DES_64_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_DES_64_CBC_WITH_SHA"))
#ifdef SSL_TXT_DES_64_CBC_WITH_SHA
	    return SSL_TXT_DES_64_CBC_WITH_SHA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_DES_64_CFB64_WITH_MD5_1"))
#ifdef SSL_TXT_DES_64_CFB64_WITH_MD5_1
	    return SSL_TXT_DES_64_CFB64_WITH_MD5_1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_IDEA_128_CBC_WITH_MD5"))
#ifdef SSL_TXT_IDEA_128_CBC_WITH_MD5
	    return SSL_TXT_IDEA_128_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_NULL"))
#ifdef SSL_TXT_NULL
	    return SSL_TXT_NULL;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_NULL_WITH_MD5"))
#ifdef SSL_TXT_NULL_WITH_MD5
	    return SSL_TXT_NULL_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_RC2_128_CBC_EXPORT40_WITH_MD5"))
#ifdef SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5
	    return SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_RC2_128_CBC_WITH_MD5"))
#ifdef SSL_TXT_RC2_128_CBC_WITH_MD5
	    return SSL_TXT_RC2_128_CBC_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_RC4_128_EXPORT40_WITH_MD5"))
#ifdef SSL_TXT_RC4_128_EXPORT40_WITH_MD5
	    return SSL_TXT_RC4_128_EXPORT40_WITH_MD5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "TXT_RC4_128_WITH_MD5"))
#ifdef SSL_TXT_RC4_128_WITH_MD5
	    return SSL_TXT_RC4_128_WITH_MD5;
#else
	    goto not_there;
#endif
#endif
	break;
    case 'U':
	break;
    case 'V':
	if (strEQ(name, "VERIFY_CLIENT_ONCE"))
#ifdef SSL_VERIFY_CLIENT_ONCE
	    return SSL_VERIFY_CLIENT_ONCE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "VERIFY_FAIL_IF_NO_PEER_CERT"))
#ifdef SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	    return SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
#else
	    goto not_there;
#endif
	if (strEQ(name, "VERIFY_NONE"))
#ifdef SSL_VERIFY_NONE
	    return SSL_VERIFY_NONE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "VERIFY_PEER"))
#ifdef SSL_VERIFY_PEER
	    return SSL_VERIFY_PEER;
#else
	    goto not_there;
#endif
	break;
    case 'W':
	if (strEQ(name, "WRITING"))
#ifdef SSL_WRITING
	    return SSL_WRITING;
#else
	    goto not_there;
#endif
	break;
    case 'X':
	if (strEQ(name, "X509_LOOKUP"))
#ifdef SSL_X509_LOOKUP
	    return SSL_X509_LOOKUP;
#else
	    goto not_there;
#endif

	if (strEQ(name, "X509_V_FLAG_CB_ISSUER_CHECK"))
#ifdef X509_V_FLAG_CB_ISSUER_CHECK
	    return X509_V_FLAG_CB_ISSUER_CHECK;
#else
	    goto not_there;
#endif

	if (strEQ(name, "X509_V_FLAG_USE_CHECK_TIME"))
#ifdef X509_V_FLAG_USE_CHECK_TIME
	    return X509_V_FLAG_USE_CHECK_TIME;
#else
	    goto not_there;
#endif
	if (strEQ(name, "X509_V_FLAG_CRL_CHECK"))
#ifdef X509_V_FLAG_CRL_CHECK
	    return X509_V_FLAG_CRL_CHECK;
#else
	    goto not_there;
#endif
	if (strEQ(name, "X509_V_FLAG_CRL_CHECK_ALL"))
#ifdef X509_V_FLAG_CRL_CHECK_ALL
	    return X509_V_FLAG_CRL_CHECK_ALL;
#else
	    goto not_there;
#endif
	if (strEQ(name, "X509_V_FLAG_IGNORE_CRITICAL"))
#ifdef X509_V_FLAG_IGNORE_CRITICAL
	    return X509_V_FLAG_IGNORE_CRITICAL;
#else
	    goto not_there;
#endif
	break;
    case 'Y':
	break;
    case 'Z':
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

