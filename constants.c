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
	if (strEQ(name, "GEN_OTHERNAME"))
#ifdef GEN_OTHERNAME
	    return GEN_OTHERNAME;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_EMAIL"))
#ifdef GEN_EMAIL
	    return GEN_EMAIL;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_DNS"))
#ifdef GEN_DNS
	    return GEN_DNS;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_X400"))
#ifdef GEN_X400
	    return GEN_X400;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_DIRNAME"))
#ifdef GEN_DIRNAME
	    return GEN_DIRNAME;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_EDIPARTY"))
#ifdef GEN_EDIPARTY
	    return GEN_EDIPARTY;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_URI"))
#ifdef GEN_URI
	    return GEN_URI;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_IPADD"))
#ifdef GEN_IPADD
	    return GEN_IPADD;
#else
	    goto not_there;
#endif
	if (strEQ(name, "GEN_RID"))
#ifdef GEN_RID
	    return GEN_RID;
#else
	    goto not_there;
#endif
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
	if (strEQ(name, "NID_undef"))
#ifdef NID_undef
	    return NID_undef;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_algorithm"))
#ifdef NID_algorithm
	    return NID_algorithm;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rsadsi"))
#ifdef NID_rsadsi
	    return NID_rsadsi;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs"))
#ifdef NID_pkcs
	    return NID_pkcs;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md2"))
#ifdef NID_md2
	    return NID_md2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md5"))
#ifdef NID_md5
	    return NID_md5;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc4"))
#ifdef NID_rc4
	    return NID_rc4;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rsaEncryption"))
#ifdef NID_rsaEncryption
	    return NID_rsaEncryption;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md2WithRSAEncryption"))
#ifdef NID_md2WithRSAEncryption
	    return NID_md2WithRSAEncryption;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md5WithRSAEncryption"))
#ifdef NID_md5WithRSAEncryption
	    return NID_md5WithRSAEncryption;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithMD2AndDES_CBC"))
#ifdef NID_pbeWithMD2AndDES_CBC
	    return NID_pbeWithMD2AndDES_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithMD5AndDES_CBC"))
#ifdef NID_pbeWithMD5AndDES_CBC
	    return NID_pbeWithMD5AndDES_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_X500"))
#ifdef NID_X500
	    return NID_X500;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_X509"))
#ifdef NID_X509
	    return NID_X509;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_commonName"))
#ifdef NID_commonName
	    return NID_commonName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_countryName"))
#ifdef NID_countryName
	    return NID_countryName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_localityName"))
#ifdef NID_localityName
	    return NID_localityName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_stateOrProvinceName"))
#ifdef NID_stateOrProvinceName
	    return NID_stateOrProvinceName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_organizationName"))
#ifdef NID_organizationName
	    return NID_organizationName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_organizationalUnitName"))
#ifdef NID_organizationalUnitName
	    return NID_organizationalUnitName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rsa"))
#ifdef NID_rsa
	    return NID_rsa;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7"))
#ifdef NID_pkcs7
	    return NID_pkcs7;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_data"))
#ifdef NID_pkcs7_data
	    return NID_pkcs7_data;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_signed"))
#ifdef NID_pkcs7_signed
	    return NID_pkcs7_signed;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_enveloped"))
#ifdef NID_pkcs7_enveloped
	    return NID_pkcs7_enveloped;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_signedAndEnveloped"))
#ifdef NID_pkcs7_signedAndEnveloped
	    return NID_pkcs7_signedAndEnveloped;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_digest"))
#ifdef NID_pkcs7_digest
	    return NID_pkcs7_digest;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs7_encrypted"))
#ifdef NID_pkcs7_encrypted
	    return NID_pkcs7_encrypted;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs3"))
#ifdef NID_pkcs3
	    return NID_pkcs3;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dhKeyAgreement"))
#ifdef NID_dhKeyAgreement
	    return NID_dhKeyAgreement;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ecb"))
#ifdef NID_des_ecb
	    return NID_des_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_cfb64"))
#ifdef NID_des_cfb64
	    return NID_des_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_cbc"))
#ifdef NID_des_cbc
	    return NID_des_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede"))
#ifdef NID_des_ede
	    return NID_des_ede;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede3"))
#ifdef NID_des_ede3
	    return NID_des_ede3;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_idea_cbc"))
#ifdef NID_idea_cbc
	    return NID_idea_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_idea_cfb64"))
#ifdef NID_idea_cfb64
	    return NID_idea_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_idea_ecb"))
#ifdef NID_idea_ecb
	    return NID_idea_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_cbc"))
#ifdef NID_rc2_cbc
	    return NID_rc2_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_ecb"))
#ifdef NID_rc2_ecb
	    return NID_rc2_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_cfb64"))
#ifdef NID_rc2_cfb64
	    return NID_rc2_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_ofb64"))
#ifdef NID_rc2_ofb64
	    return NID_rc2_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sha"))
#ifdef NID_sha
	    return NID_sha;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_shaWithRSAEncryption"))
#ifdef NID_shaWithRSAEncryption
	    return NID_shaWithRSAEncryption;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede_cbc"))
#ifdef NID_des_ede_cbc
	    return NID_des_ede_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede3_cbc"))
#ifdef NID_des_ede3_cbc
	    return NID_des_ede3_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ofb64"))
#ifdef NID_des_ofb64
	    return NID_des_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_idea_ofb64"))
#ifdef NID_idea_ofb64
	    return NID_idea_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9"))
#ifdef NID_pkcs9
	    return NID_pkcs9;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_emailAddress"))
#ifdef NID_pkcs9_emailAddress
	    return NID_pkcs9_emailAddress;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_unstructuredName"))
#ifdef NID_pkcs9_unstructuredName
	    return NID_pkcs9_unstructuredName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_contentType"))
#ifdef NID_pkcs9_contentType
	    return NID_pkcs9_contentType;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_messageDigest"))
#ifdef NID_pkcs9_messageDigest
	    return NID_pkcs9_messageDigest;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_signingTime"))
#ifdef NID_pkcs9_signingTime
	    return NID_pkcs9_signingTime;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_countersignature"))
#ifdef NID_pkcs9_countersignature
	    return NID_pkcs9_countersignature;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_challengePassword"))
#ifdef NID_pkcs9_challengePassword
	    return NID_pkcs9_challengePassword;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_unstructuredAddress"))
#ifdef NID_pkcs9_unstructuredAddress
	    return NID_pkcs9_unstructuredAddress;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs9_extCertAttributes"))
#ifdef NID_pkcs9_extCertAttributes
	    return NID_pkcs9_extCertAttributes;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape"))
#ifdef NID_netscape
	    return NID_netscape;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_cert_extension"))
#ifdef NID_netscape_cert_extension
	    return NID_netscape_cert_extension;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_data_type"))
#ifdef NID_netscape_data_type
	    return NID_netscape_data_type;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede_cfb64"))
#ifdef NID_des_ede_cfb64
	    return NID_des_ede_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede3_cfb64"))
#ifdef NID_des_ede3_cfb64
	    return NID_des_ede3_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede_ofb64"))
#ifdef NID_des_ede_ofb64
	    return NID_des_ede_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_des_ede3_ofb64"))
#ifdef NID_des_ede3_ofb64
	    return NID_des_ede3_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sha1"))
#ifdef NID_sha1
	    return NID_sha1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sha1WithRSAEncryption"))
#ifdef NID_sha1WithRSAEncryption
	    return NID_sha1WithRSAEncryption;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dsaWithSHA"))
#ifdef NID_dsaWithSHA
	    return NID_dsaWithSHA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dsa_2"))
#ifdef NID_dsa_2
	    return NID_dsa_2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithSHA1AndRC2_CBC"))
#ifdef NID_pbeWithSHA1AndRC2_CBC
	    return NID_pbeWithSHA1AndRC2_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_pbkdf2"))
#ifdef NID_id_pbkdf2
	    return NID_id_pbkdf2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dsaWithSHA1_2"))
#ifdef NID_dsaWithSHA1_2
	    return NID_dsaWithSHA1_2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_cert_type"))
#ifdef NID_netscape_cert_type
	    return NID_netscape_cert_type;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_base_url"))
#ifdef NID_netscape_base_url
	    return NID_netscape_base_url;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_revocation_url"))
#ifdef NID_netscape_revocation_url
	    return NID_netscape_revocation_url;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_ca_revocation_url"))
#ifdef NID_netscape_ca_revocation_url
	    return NID_netscape_ca_revocation_url;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_renewal_url"))
#ifdef NID_netscape_renewal_url
	    return NID_netscape_renewal_url;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_ca_policy_url"))
#ifdef NID_netscape_ca_policy_url
	    return NID_netscape_ca_policy_url;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_ssl_server_name"))
#ifdef NID_netscape_ssl_server_name
	    return NID_netscape_ssl_server_name;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_comment"))
#ifdef NID_netscape_comment
	    return NID_netscape_comment;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_netscape_cert_sequence"))
#ifdef NID_netscape_cert_sequence
	    return NID_netscape_cert_sequence;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_desx_cbc"))
#ifdef NID_desx_cbc
	    return NID_desx_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_ce"))
#ifdef NID_id_ce
	    return NID_id_ce;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_subject_key_identifier"))
#ifdef NID_subject_key_identifier
	    return NID_subject_key_identifier;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_key_usage"))
#ifdef NID_key_usage
	    return NID_key_usage;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_private_key_usage_period"))
#ifdef NID_private_key_usage_period
	    return NID_private_key_usage_period;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_subject_alt_name"))
#ifdef NID_subject_alt_name
	    return NID_subject_alt_name;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_issuer_alt_name"))
#ifdef NID_issuer_alt_name
	    return NID_issuer_alt_name;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_basic_constraints"))
#ifdef NID_basic_constraints
	    return NID_basic_constraints;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_crl_number"))
#ifdef NID_crl_number
	    return NID_crl_number;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_certificate_policies"))
#ifdef NID_certificate_policies
	    return NID_certificate_policies;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_authority_key_identifier"))
#ifdef NID_authority_key_identifier
	    return NID_authority_key_identifier;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_bf_cbc"))
#ifdef NID_bf_cbc
	    return NID_bf_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_bf_ecb"))
#ifdef NID_bf_ecb
	    return NID_bf_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_bf_cfb64"))
#ifdef NID_bf_cfb64
	    return NID_bf_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_bf_ofb64"))
#ifdef NID_bf_ofb64
	    return NID_bf_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_mdc2"))
#ifdef NID_mdc2
	    return NID_mdc2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_mdc2WithRSA"))
#ifdef NID_mdc2WithRSA
	    return NID_mdc2WithRSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc4_40"))
#ifdef NID_rc4_40
	    return NID_rc4_40;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_40_cbc"))
#ifdef NID_rc2_40_cbc
	    return NID_rc2_40_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_givenName"))
#ifdef NID_givenName
	    return NID_givenName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_surname"))
#ifdef NID_surname
	    return NID_surname;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_initials"))
#ifdef NID_initials
	    return NID_initials;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_uniqueIdentifier"))
#ifdef NID_uniqueIdentifier
	    return NID_uniqueIdentifier;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_crl_distribution_points"))
#ifdef NID_crl_distribution_points
	    return NID_crl_distribution_points;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md5WithRSA"))
#ifdef NID_md5WithRSA
	    return NID_md5WithRSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_serialNumber"))
#ifdef NID_serialNumber
	    return NID_serialNumber;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_title"))
#ifdef NID_title
	    return NID_title;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_description"))
#ifdef NID_description
	    return NID_description;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_cast5_cbc"))
#ifdef NID_cast5_cbc
	    return NID_cast5_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_cast5_ecb"))
#ifdef NID_cast5_ecb
	    return NID_cast5_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_cast5_cfb64"))
#ifdef NID_cast5_cfb64
	    return NID_cast5_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_cast5_ofb64"))
#ifdef NID_cast5_ofb64
	    return NID_cast5_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithMD5AndCast5_CBC"))
#ifdef NID_pbeWithMD5AndCast5_CBC
	    return NID_pbeWithMD5AndCast5_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dsaWithSHA1"))
#ifdef NID_dsaWithSHA1
	    return NID_dsaWithSHA1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_md5_sha1"))
#ifdef NID_md5_sha1
	    return NID_md5_sha1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sha1WithRSA"))
#ifdef NID_sha1WithRSA
	    return NID_sha1WithRSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dsa"))
#ifdef NID_dsa
	    return NID_dsa;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ripemd160"))
#ifdef NID_ripemd160
	    return NID_ripemd160;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ripemd160WithRSA"))
#ifdef NID_ripemd160WithRSA
	    return NID_ripemd160WithRSA;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc5_cbc"))
#ifdef NID_rc5_cbc
	    return NID_rc5_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc5_ecb"))
#ifdef NID_rc5_ecb
	    return NID_rc5_ecb;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc5_cfb64"))
#ifdef NID_rc5_cfb64
	    return NID_rc5_cfb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc5_ofb64"))
#ifdef NID_rc5_ofb64
	    return NID_rc5_ofb64;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rle_compression"))
#ifdef NID_rle_compression
	    return NID_rle_compression;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_zlib_compression"))
#ifdef NID_zlib_compression
	    return NID_zlib_compression;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ext_key_usage"))
#ifdef NID_ext_key_usage
	    return NID_ext_key_usage;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_pkix"))
#ifdef NID_id_pkix
	    return NID_id_pkix;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_kp"))
#ifdef NID_id_kp
	    return NID_id_kp;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_server_auth"))
#ifdef NID_server_auth
	    return NID_server_auth;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_client_auth"))
#ifdef NID_client_auth
	    return NID_client_auth;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_code_sign"))
#ifdef NID_code_sign
	    return NID_code_sign;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_email_protect"))
#ifdef NID_email_protect
	    return NID_email_protect;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_time_stamp"))
#ifdef NID_time_stamp
	    return NID_time_stamp;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_code_ind"))
#ifdef NID_ms_code_ind
	    return NID_ms_code_ind;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_code_com"))
#ifdef NID_ms_code_com
	    return NID_ms_code_com;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_ctl_sign"))
#ifdef NID_ms_ctl_sign
	    return NID_ms_ctl_sign;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_sgc"))
#ifdef NID_ms_sgc
	    return NID_ms_sgc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_efs"))
#ifdef NID_ms_efs
	    return NID_ms_efs;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ns_sgc"))
#ifdef NID_ns_sgc
	    return NID_ns_sgc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_delta_crl"))
#ifdef NID_delta_crl
	    return NID_delta_crl;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_crl_reason"))
#ifdef NID_crl_reason
	    return NID_crl_reason;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_invalidity_date"))
#ifdef NID_invalidity_date
	    return NID_invalidity_date;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sxnet"))
#ifdef NID_sxnet
	    return NID_sxnet;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And128BitRC4"))
#ifdef NID_pbe_WithSHA1And128BitRC4
	    return NID_pbe_WithSHA1And128BitRC4;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And40BitRC4"))
#ifdef NID_pbe_WithSHA1And40BitRC4
	    return NID_pbe_WithSHA1And40BitRC4;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And3_Key_TripleDES_CBC"))
#ifdef NID_pbe_WithSHA1And3_Key_TripleDES_CBC
	    return NID_pbe_WithSHA1And3_Key_TripleDES_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And2_Key_TripleDES_CBC"))
#ifdef NID_pbe_WithSHA1And2_Key_TripleDES_CBC
	    return NID_pbe_WithSHA1And2_Key_TripleDES_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And128BitRC2_CBC"))
#ifdef NID_pbe_WithSHA1And128BitRC2_CBC
	    return NID_pbe_WithSHA1And128BitRC2_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbe_WithSHA1And40BitRC2_CBC"))
#ifdef NID_pbe_WithSHA1And40BitRC2_CBC
	    return NID_pbe_WithSHA1And40BitRC2_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_keyBag"))
#ifdef NID_keyBag
	    return NID_keyBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pkcs8ShroudedKeyBag"))
#ifdef NID_pkcs8ShroudedKeyBag
	    return NID_pkcs8ShroudedKeyBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_certBag"))
#ifdef NID_certBag
	    return NID_certBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_crlBag"))
#ifdef NID_crlBag
	    return NID_crlBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_secretBag"))
#ifdef NID_secretBag
	    return NID_secretBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_safeContentsBag"))
#ifdef NID_safeContentsBag
	    return NID_safeContentsBag;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_friendlyName"))
#ifdef NID_friendlyName
	    return NID_friendlyName;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_localKeyID"))
#ifdef NID_localKeyID
	    return NID_localKeyID;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_x509Certificate"))
#ifdef NID_x509Certificate
	    return NID_x509Certificate;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_sdsiCertificate"))
#ifdef NID_sdsiCertificate
	    return NID_sdsiCertificate;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_x509Crl"))
#ifdef NID_x509Crl
	    return NID_x509Crl;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbes2"))
#ifdef NID_pbes2
	    return NID_pbes2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbmac1"))
#ifdef NID_pbmac1
	    return NID_pbmac1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_hmacWithSHA1"))
#ifdef NID_hmacWithSHA1
	    return NID_hmacWithSHA1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_qt_cps"))
#ifdef NID_id_qt_cps
	    return NID_id_qt_cps;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_qt_unotice"))
#ifdef NID_id_qt_unotice
	    return NID_id_qt_unotice;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_rc2_64_cbc"))
#ifdef NID_rc2_64_cbc
	    return NID_rc2_64_cbc;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_SMIMECapabilities"))
#ifdef NID_SMIMECapabilities
	    return NID_SMIMECapabilities;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithMD2AndRC2_CBC"))
#ifdef NID_pbeWithMD2AndRC2_CBC
	    return NID_pbeWithMD2AndRC2_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithMD5AndRC2_CBC"))
#ifdef NID_pbeWithMD5AndRC2_CBC
	    return NID_pbeWithMD5AndRC2_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_pbeWithSHA1AndDES_CBC"))
#ifdef NID_pbeWithSHA1AndDES_CBC
	    return NID_pbeWithSHA1AndDES_CBC;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ms_ext_req"))
#ifdef NID_ms_ext_req
	    return NID_ms_ext_req;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ext_req"))
#ifdef NID_ext_req
	    return NID_ext_req;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_name"))
#ifdef NID_name
	    return NID_name;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_dnQualifier"))
#ifdef NID_dnQualifier
	    return NID_dnQualifier;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_pe"))
#ifdef NID_id_pe
	    return NID_id_pe;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_id_ad"))
#ifdef NID_id_ad
	    return NID_id_ad;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_info_access"))
#ifdef NID_info_access
	    return NID_info_access;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ad_OCSP"))
#ifdef NID_ad_OCSP
	    return NID_ad_OCSP;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_ad_ca_issuers"))
#ifdef NID_ad_ca_issuers
	    return NID_ad_ca_issuers;
#else
	    goto not_there;
#endif
	if (strEQ(name, "NID_OCSP_sign"))
#ifdef NID_OCSP_sign
	    return NID_OCSP_sign;
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
	if (strEQ(name, "OP_NO_TICKET"))
#ifdef SSL_OP_NO_TICKET
	    return SSL_OP_NO_TICKET;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_TLSv1"))
#ifdef SSL_OP_NO_TLSv1
	    return SSL_OP_NO_TLSv1;
#else
	    goto not_there;
#endif


	if (strEQ(name, "OP_NO_QUERY_MTU"))
#ifdef SSL_OP_NO_QUERY_MTU
	    return SSL_OP_NO_QUERY_MTU;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_COOKIE_EXCHANGE"))
#ifdef SSL_OP_COOKIE_EXCHANGE
	    return SSL_OP_COOKIE_EXCHANGE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION"))
#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
	    return SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NO_COMPRESSION"))
#ifdef SSL_OP_NO_COMPRESSION
	    return SSL_OP_NO_COMPRESSION;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_CIPHER_SERVER_PREFERENCE"))
#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
	    return SSL_OP_CIPHER_SERVER_PREFERENCE;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_TLS_ROLLBACK_BUG"))
#ifdef SSL_OP_TLS_ROLLBACK_BUG
	    return SSL_OP_TLS_ROLLBACK_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_PKCS1_CHECK_1"))
#ifdef SSL_OP_PKCS1_CHECK_1
	    return SSL_OP_PKCS1_CHECK_1;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_PKCS1_CHECK_2"))
#ifdef SSL_OP_PKCS1_CHECK_2
	    return SSL_OP_PKCS1_CHECK_2;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_CA_DN_BUG"))
#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
	    return SSL_OP_NETSCAPE_CA_DN_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG"))
#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
	    return SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;
#else
	    goto not_there;
#endif
	if (strEQ(name, "OP_DONT_INSERT_EMPTY_FRAGMENTS"))
#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
	    return SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
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
        if (strEQ(name, "RECEIVED_SHUTDOWN"))
#ifdef SSL_RECEIVED_SHUTDOWN
                return SSL_RECEIVED_SHUTDOWN;
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
        if (strEQ(name, "SENT_SHUTDOWN"))
#ifdef SSL_SENT_SHUTDOWN
                return SSL_SENT_SHUTDOWN;
#else
                goto not_there;
#endif
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
	case '_':
	if (strEQ(name, "_TEST_INVALID_CONSTANT"))
		goto not_there;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}

