/* SSLeay.xs - Perl module for using Eric Young's implementation of SSL
 *
 * Copyright (c) 1996-2002 Sampo Kellomaki <sampo@iki.fi>
 * Copyright (C) 2005 Florian Ragwitz <rafl@debian.org>
 * Copyright (C) 2005 Mike McCauley <mikem@open.com.au>
 * 
 * All Rights Reserved.
 *
 * 19.6.1998, Maintenance release to sync with SSLeay-0.9.0, --Sampo
 * 24.6.1998, added write_partial to support ssl_write_all in more
 *            memory efficient way. --Sampo
 * 8.7.1998,  Added SSL_(CTX)?_set_options and associated constants.
 * 31.3.1999, Tracking OpenSSL-0.9.2b changes, dropping support for
 *            earlier versions
 * 30.7.1999, Tracking OpenSSL-0.9.3a changes, --Sampo
 * 7.4.2001,  OpenSSL-0.9.6a update, --Sampo
 * 18.4.2001, added TLSv1 support by Stephen C. Koehler
 *            <koehler@securecomputing.com>, version 1.07, --Sampo
 * 25.4.2001, applied 64 bit fixes by Marko Asplund <aspa@kronodoc.fi> --Sampo
 * 16.7.2001, applied Win filehandle patch from aspa, added
 *            SSL_*_methods --Sampo
 * 25.9.2001, added a big pile of methods by automatically grepping and diffing
 *            openssl headers and my module --Sampo
 * 17.4.2002, applied patch to fix CTX_set_default_passwd_cb() contributed
 *            by Timo Kujala <timo.kujala@@intellitel_.com>, --Sampo
 * 17.5.2002, Added BIO_s_mem, BIO_new, BIO_free, BIO_write, BIO_read ,
 *            BIO_eof, BIO_pending, BIO_wpending, X509_NAME_get_text_by_NID,
 *            RSA_generate_key, BIO_new_file
 *            Fixed problem with return value from verify callback being
 *            ignored.
 *            Fixed a problem with CTX_set_tmp_rsa and CTX_set_tmp_dh
 *            args incorrect
 *            --mikem@open.com_.au
 * 10.8.2002, Added SSL_peek patch to ssl_read_until from 
 *            Peter Behroozi <peter@@fhpwireless_.com> --Sampo
 * 21.8.2002, Added SESSION_get_master_key, SSL_get_client_random, SSL_get_server_random
 *            --mikem@open.com_.au
 * 2.9.2002,  Added SSL_CTX_get_cert_store, X509_STORE_add_cert, X509_STORE_add_crl
 *            X509_STORE_set_flags, X509_load_cert_file, X509_load_crl_file
 *            X509_load_cert_crl_file, PEM_read_bio_X509_CRL
 *            constants for X509_V_FLAG_*
 *            --mikem@open.com_.au
 * 6.9.2002,  applied Mike's patch and fixed X509_STORE_* to X509_STORE_CTX_*
 *	      --Sampo
 * 18.2.2003, RAND patch from Toni Andjelkovic <toni@soth._at>
 * 13.6.2003, applied SSL_X509_LOOKUP patch by Marian Jancar <mjancar@suse._cz>
 * 18.8.2003, fixed some const char pointer warnings --Sampo
 * 01.12.2005 fixed a thread safety problem with SvSetSV that could cause crashes
 *            if SSL_CTX_set_default_passwd_cb and friends were called multiple
 *            times in different threads.
 *	      Reintroduced X509_STORE_set_flags, also added
 *	      X509_STORE_set_purpose and X509_STORE_set_trust
 *	      Added X509_get_subjectAltNames and a number of other openssl
 *            X509 functions: X509_get_ext_by_NID X509_get_ext
 *	      X509V3_EXT_d2i
 *	      X509_verify_cert_error_string
 *            --mikem@open.com_.au
 * 13.12.2005 Reinstated the thread safety fix from 01.12.2005 due memory leaks
 *	      It is better to reset the callback with undef after use to prevent
 *	      leaks and thread safety problems.
 *
 * $Id$
 * 
 * The distribution and use of this module are subject to the conditions
 * listed in LICENSE file at the root of OpenSSL-0.9.6b
 * distribution (i.e. free, but mandatory attribution and NO WARRANTY).
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"
#ifdef __cplusplus
}
#endif

/* OpenSSL-0.9.3a has some strange warning about this in
 *    openssl/des.h
 */
#undef _

#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/comp.h>    /* openssl-0.9.6a forgets to include this */
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>     /* openssl-SNAP-20020227 does not automatically include this */
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Debugging output */

#if 0
#define PR(s) printf(s);
#define PRN(s,n) printf("'%s' (%d)\n",s,n);
#define SEX_DEBUG 1
#else
#define PR(s)
#define PRN(s,n)
#undef  SEX_DEBUG
#endif

#include "constants.c"

/* ============= typedefs to agument TYPEMAP ============== */

typedef void generate_key_cb (int, int, void *);
typedef int callback_ret_int();
typedef void callback_no_ret();
typedef RSA * cb_ssl_int_int_ret_RSA(SSL * ssl,int is_export, int keylength);
typedef DH * cb_ssl_int_int_ret_DH(SSL * ssl,int is_export, int keylength);

typedef STACK_OF(X509_NAME) X509_NAME_STACK;

typedef int perl_filehandle_t;

/* ============= callback stuff ============== */

static HV* ssleay_ctx_verify_callbacks = (HV*)NULL;

static int
ssleay_verify_callback_invoke (int ok, X509_STORE_CTX* x509_store) {
	SSL* ssl;
	SV* key;
	char* key_str;
	STRLEN key_len;
	SV** callback;
	int count, res;

	ssl = X509_STORE_CTX_get_ex_data( x509_store, SSL_get_ex_data_X509_STORE_CTX_idx() );
	key = sv_2mortal(newSViv( (IV)ssl ));
	key_str = SvPV(key, key_len);

	callback = hv_fetch( ssleay_ctx_verify_callbacks, key_str, key_len, 0 );

	if (callback == NULL) {
		SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
		key = sv_2mortal(newSViv( (IV)ssl_ctx ));
		key_str = SvPV(key, key_len);

		callback = hv_fetch( ssleay_ctx_verify_callbacks, key_str, key_len, 0 );

		if (callback == NULL) {
			croak ("Net::SSLeay: verify_callback called, but not "
				"set to point to any perl function.\n");
		}
	}

	dSP;

	ENTER;
	SAVETMPS;

	PRN("verify callback glue", ok);

	PUSHMARK(sp);
	XPUSHs( sv_2mortal(newSViv(ok)) );
	XPUSHs( sv_2mortal(newSViv((unsigned long int)x509_store)) );
	PUTBACK;

	PR("About to call verify callback.\n");
	count = call_sv(*callback, G_SCALAR);
	PR("Returned from verify callback.\n");

	SPAGAIN;

	if (count != 1) {
		croak ( "Net::SSLeay: verify_callback "
			"perl function did not return a scalar.\n");
	}

	res = POPi;

	PUTBACK;
	FREETMPS;
	LEAVE;

	return res;
}

static HV* ssleay_ctx_passwd_cbs = (HV*)NULL;

struct _ssleay_ctx_passwd_cb_t {
	SV* func;
	SV* data;
};
typedef struct _ssleay_ctx_passwd_cb_t ssleay_ctx_passwd_cb_t;

ssleay_ctx_passwd_cb_t*
ssleay_ctx_passwd_cb_new(SSL_CTX* ctx) {
	ssleay_ctx_passwd_cb_t* cb;
	SV* hash_value;
	SV* key;
	char* key_str;
	STRLEN key_len;

	cb = (ssleay_ctx_passwd_cb_t*)malloc( sizeof(ssleay_ctx_passwd_cb_t) );

	if (ctx == NULL)
		croak( "Net::SSLeay: ctx == NULL in ssleay_ctx_passwd_cb_new" );

	hash_value = sv_2mortal(newSViv( (IV)cb ));

	key = sv_2mortal(newSViv( (IV)ctx ));
	key_str = SvPV(key, key_len);

	if (ssleay_ctx_passwd_cbs == (HV*)NULL)
		ssleay_ctx_passwd_cbs = newHV();

	SvREFCNT_inc(hash_value);
	hv_store( ssleay_ctx_passwd_cbs, key_str, key_len, hash_value, 0 );

	return cb;
}

ssleay_ctx_passwd_cb_t*
ssleay_ctx_passwd_cb_get(SSL_CTX* ctx) {
	SV* key;
	char* key_str;
	STRLEN key_len;
	SV** hash_value;
	ssleay_ctx_passwd_cb_t* cb;

	key = sv_2mortal(newSViv( (IV)ctx ));
	key_str = SvPV(key, key_len);

	hash_value = hv_fetch( ssleay_ctx_passwd_cbs, key_str, key_len, 0 );

	if (hash_value == NULL || *hash_value == NULL) {
		cb = ssleay_ctx_passwd_cb_new(ctx);
	} else {
		cb = (ssleay_ctx_passwd_cb_t*)SvIV( *hash_value );
	}

	return cb;

}

void
ssleay_ctx_passwd_cb_func_set(SSL_CTX* ctx, SV* func) {
	ssleay_ctx_passwd_cb_t* cb;

	cb = ssleay_ctx_passwd_cb_get(ctx);

	SvREFCNT_inc(func);
	cb->func = func;
}

void
ssleay_ctx_passwd_cb_userdata_set(SSL_CTX* ctx, SV* data) {
	ssleay_ctx_passwd_cb_t* cb;

	cb = ssleay_ctx_passwd_cb_get(ctx);
	
	SvREFCNT_inc(data);
	cb->data = data;
}

void ssleay_ctx_passwd_cb_free(SSL_CTX* ctx) {
	ssleay_ctx_passwd_cb_t* cb;

	cb = ssleay_ctx_passwd_cb_get(ctx);

	if (cb) {
		if (cb->func) {
			SvREFCNT_dec(cb->func);
			cb->func = NULL;
		}

		if (cb->data) {
			SvREFCNT_dec(cb->data);
			cb->data = NULL;
		}
	}

	/* TODO dec refcnt for hash key */
}

/* pem_password_cb function */

static int
ssleay_ctx_passwd_cb_invoke(char *buf, int size, int rwflag, void *userdata) {
	dSP;

	int count;
	char *res;
	ssleay_ctx_passwd_cb_t* cb = (ssleay_ctx_passwd_cb_t*)userdata;

	ENTER;
	SAVETMPS;

	PUSHMARK(sp);
	XPUSHs( sv_2mortal( newSViv(rwflag)) );
	if (cb->data)
		XPUSHs( cb->data );
	PUTBACK;

	if (cb->func == NULL)
		croak ("Net::SSLeay: ssleay_ctx_passwd_cb_invoke called, but not "
			   "set to point to any perl function.\n");

	count = call_sv( cb->func, G_SCALAR );

	SPAGAIN;

	if (count != 1)
		croak ("Net::SSLeay: ssleay_ctx_passwd_cb_invoke "
			   "perl function did not return a scalar.\n");

	res = POPp;

	if (res == NULL) {
		*buf = '\0';
	} else {
		strncpy(buf, res, size);
		buf[size - 1] = '\0';
	}

	PUTBACK;
	FREETMPS;
	LEAVE;

	return strlen(buf);
}

MODULE = Net::SSLeay		PACKAGE = Net::SSLeay          PREFIX = SSL_

PROTOTYPES: ENABLE

double
constant(name)
     char *		name

int
hello()
        CODE:
        PR("\tSSLeay Hello World!\n");
        RETVAL = 1;
        OUTPUT:
        RETVAL

#define REM1 "============= SSL CONTEXT functions =============="

SSL_CTX *
SSL_CTX_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv23_method());
     OUTPUT:
     RETVAL

SSL_CTX *
SSL_CTX_v2_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv2_method());
     OUTPUT:
     RETVAL

SSL_CTX *
SSL_CTX_v3_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv3_method());
     OUTPUT:
     RETVAL

SSL_CTX *
SSL_CTX_v23_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv23_method());
     OUTPUT:
     RETVAL

SSL_CTX *
SSL_CTX_tlsv1_new()
     CODE:
     RETVAL = SSL_CTX_new (TLSv1_method());
     OUTPUT:
     RETVAL

SSL_CTX *
SSL_CTX_new_with_method(meth)
     CODE:
     RETVAL = SSL_CTX_new (SSLv23_method());
     OUTPUT:
     RETVAL

void
SSL_CTX_free(ctx)
     SSL_CTX *	        ctx

int
SSL_CTX_add_session(ctx,ses)
     SSL_CTX *          ctx
     SSL_SESSION *      ses

int
SSL_CTX_remove_session(ctx,ses)
     SSL_CTX *          ctx
     SSL_SESSION *      ses

void
SSL_CTX_flush_sessions(ctx,tm)
     SSL_CTX *          ctx
     long               tm

int
SSL_CTX_set_default_verify_paths(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_load_verify_locations(ctx,CAfile,CApath)
     SSL_CTX * ctx
     char * CAfile
     char * CApath
     CODE:
     RETVAL = SSL_CTX_load_verify_locations (ctx,
					     CAfile?(*CAfile?CAfile:NULL):NULL,
					     CApath?(*CApath?CApath:NULL):NULL
					     );
     OUTPUT:
     RETVAL

void
SSL_CTX_set_verify(ctx,mode,callback=NULL)
	SSL_CTX * ctx
	int                mode
	SV *               callback
	PREINIT:
	SV* key;
	char* key_str;
	STRLEN key_len;
	CODE:

	if (ssleay_ctx_verify_callbacks == (HV*)NULL)
		ssleay_ctx_verify_callbacks = newHV();

	key = sv_2mortal(newSViv( (IV)ctx ));
	key_str = SvPV(key, key_len);

	if (callback == NULL) {
		hv_delete( ssleay_ctx_verify_callbacks, key_str, key_len, G_DISCARD );
		SSL_CTX_set_verify( ctx, mode, NULL );
	} else {
		hv_store( ssleay_ctx_verify_callbacks, key_str, key_len, newSVsv(callback), 0 );
		SSL_CTX_set_verify( ctx, mode, &ssleay_verify_callback_invoke );
	}

int
SSL_get_error(s,ret)
     SSL *              s
     int ret

#define REM10 "============= SSL functions =============="

SSL *
SSL_new(ctx)
     SSL_CTX *	        ctx

void
SSL_free(s)
     SSL *              s

#if 0 /* this seems to be gone in 0.9.0 */
void
SSL_debug(file)
       char *  file

#endif

int
SSL_accept(s)
     SSL *   s

void
SSL_clear(s)
     SSL *   s

int
SSL_connect(s)
     SSL *   s


#if defined(WIN32)

int
SSL_set_fd(s,fd)
     SSL *   s
     int     fd
     CODE:
     RETVAL = SSL_set_fd(s,_get_osfhandle(fd));
     OUTPUT:
     RETVAL

int
SSL_set_rfd(s,fd)
     SSL *   s
     int     fd
     CODE:
     RETVAL = SSL_set_rfd(s,_get_osfhandle(fd));
     OUTPUT:
     RETVAL

int
SSL_set_wfd(s,fd)
     SSL *   s
     int     fd
     CODE:
     RETVAL = SSL_set_wfd(s,_get_osfhandle(fd));
     OUTPUT:
     RETVAL

#else

int
SSL_set_fd(s,fd)
     SSL *   s
     perl_filehandle_t     fd

int
SSL_set_rfd(s,fd)
     SSL *   s
     perl_filehandle_t     fd

int
SSL_set_wfd(s,fd)
     SSL *   s
     perl_filehandle_t     fd

#endif

int
SSL_get_fd(s)
     SSL *   s

void
SSL_read(s,max=32768)
	SSL *   s
	int     max
	PREINIT:
	char *buf;
	int got;
	CODE:
	buf = (char*)malloc( sizeof(char) * max );
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = SSL_read(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	free(buf);

void
SSL_peek(s,max=32768)
	SSL *   s
	int     max
	PREINIT:
	char *buf;
	int got;
	CODE:
	buf = (char*)malloc( sizeof(char) * max );
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = SSL_peek(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	free(buf);

int
SSL_write(s,buf)
     SSL *   s
     PREINIT:
     STRLEN len;
     INPUT:
     char *  buf = SvPV( ST(1), len);
     CODE:
     RETVAL = SSL_write (s, buf, (int)len);
     OUTPUT:
     RETVAL

int
SSL_write_partial(s,from,count,buf)
     SSL *   s
     int     from
     int     count
     PREINIT:
     STRLEN len;
     INPUT:
     char *  buf = SvPV( ST(3), len);
     CODE:
      /*
     if (SvROK( ST(3) )) {
       SV* t = SvRV( ST(3) );
       buf = SvPV( t, len);
     } else
       buf = SvPV( ST(3), len);
       */
     PRN("write_partial from",from);
     PRN(&buf[from],len);
     PRN("write_partial count",count);
     len -= from;
     if (len < 0) {
       croak("from beyound end of buffer");
       RETVAL = -1;
     } else
       RETVAL = SSL_write (s, &(buf[from]), (count<=len)?count:len);
     OUTPUT:
     RETVAL

int
SSL_use_RSAPrivateKey(s,rsa)
     SSL *              s
     RSA *              rsa

int
SSL_use_RSAPrivateKey_ASN1(s,d,len)
     SSL *              s
     unsigned char *    d
     long               len

int
SSL_use_RSAPrivateKey_file(s,file,type)
     SSL *              s
     char *             file
     int                type

int
SSL_CTX_use_RSAPrivateKey_file(ctx,file,type)
     SSL_CTX *          ctx
     char *             file
     int                type

int
SSL_use_PrivateKey(s,pkey)
     SSL *              s
     EVP_PKEY *         pkey

int
SSL_use_PrivateKey_ASN1(pk,s,d,len)
     int                pk
     SSL *              s
     unsigned char *    d
     long               len

int
SSL_use_PrivateKey_file(s,file,type)
     SSL *              s
     char *             file
     int                type

int
SSL_CTX_use_PrivateKey_file(ctx,file,type)
     SSL_CTX *          ctx
     char *             file
     int                type

int
SSL_use_certificate(s,x)
     SSL *              s
     X509 *             x

int
SSL_use_certificate_ASN1(s,d,len)
     SSL *              s
     unsigned char *    d
     long               len

int
SSL_use_certificate_file(s,file,type)
     SSL *              s
     char *             file
     int                type

int
SSL_CTX_use_certificate_file(ctx,file,type)
     SSL_CTX *          ctx
     char *             file
     int                type

const char *
SSL_state_string(s)
     SSL *              s

const char *
SSL_rstate_string(s)
     SSL *              s

const char *
SSL_state_string_long(s)
     SSL *              s

const char *
SSL_rstate_string_long(s)
     SSL *              s


long
SSL_get_time(ses)
     SSL_SESSION *      ses

long
SSL_set_time(ses,t)
     SSL_SESSION *      ses
     long               t

long
SSL_get_timeout(ses)
     SSL_SESSION *      ses

long
SSL_set_timeout(ses,t)
     SSL_SESSION *      ses
     long               t

void
SSL_copy_session_id(to,from)
     SSL *              to
     SSL *              from

void
SSL_set_read_ahead(s,yes=1)
     SSL *              s
     int                yes

int
SSL_get_read_ahead(s)
     SSL *              s

int
SSL_pending(s)
     SSL *              s

int
SSL_CTX_set_cipher_list(s,str)
     SSL_CTX *              s
     char *             str

const char *
SSL_get_cipher_list(s,n)
     SSL *              s
     int                n

int
SSL_set_cipher_list(s,str)
     SSL *              s
     char *       str

const char *
SSL_get_cipher(s)
     SSL *              s

char *
SSL_get_shared_ciphers(s,buf,len)
     SSL *              s
     char *             buf
     int                len

X509 *
SSL_get_peer_certificate(s)
     SSL *              s

void
SSL_set_verify(s,mode,callback)
    SSL *              s
    int                mode
    SV *               callback
	PREINIT:
	SV* key;
	char* key_str;
	STRLEN key_len;
    CODE:

	if (ssleay_ctx_verify_callbacks == (HV*)NULL)
		ssleay_ctx_verify_callbacks = newHV();

	key = sv_2mortal(newSViv( (IV)s ));
	key_str = SvPV(key, key_len);

	if (callback == NULL) {
		hv_delete( ssleay_ctx_verify_callbacks, key_str, key_len, G_DISCARD );
		SSL_set_verify( s, mode, NULL );
	} else {
		hv_store( ssleay_ctx_verify_callbacks, key_str, key_len, newSVsv(callback), 0 );
		SSL_set_verify( s, mode, &ssleay_verify_callback_invoke );
	}

void
SSL_set_bio(s,rbio,wbio)
     SSL *              s
     BIO *              rbio
     BIO *              wbio

BIO *
SSL_get_rbio(s)
     SSL *              s

BIO *
SSL_get_wbio(s)
     SSL *              s


SSL_SESSION *
SSL_SESSION_new()

int
SSL_SESSION_print(fp,ses)
     BIO *              fp
     SSL_SESSION *      ses

void
SSL_SESSION_free(ses)
     SSL_SESSION *      ses

int
i2d_SSL_SESSION(in,pp)
     SSL_SESSION *      in
     unsigned char *    &pp

int
SSL_set_session(to,ses)
     SSL *              to
     SSL_SESSION *      ses

SSL_SESSION *
d2i_SSL_SESSION(a,pp,length)
     SSL_SESSION *      &a
     const unsigned char *    &pp
     long               length

#define REM30 "SSLeay-0.9.0 defines these as macros. I expand them here for safety's sake"

SSL_SESSION *
SSL_get_session(s)
	SSL *              s
	ALIAS:
		SSL_get0_session = 1

SSL_SESSION *
SSL_get1_session(s)
     SSL *              s

X509 *
SSL_get_certificate(s)
     SSL *              s

SSL_CTX *
SSL_get_SSL_CTX(s)
     SSL *              s

long
SSL_ctrl(ssl,cmd,larg,parg)
	 SSL * ssl
	 int cmd
	 long larg
	 char * parg

long
SSL_CTX_ctrl(ctx,cmd,larg,parg)
    SSL_CTX * ctx
    int cmd
    long larg
    char * parg

long
SSL_get_options(ssl)
     SSL *          ssl

void
SSL_set_options(ssl,op)
     SSL *          ssl
     long	    op

long
SSL_CTX_get_options(ctx)
     SSL_CTX *      ctx

void
SSL_CTX_set_options(ctx,op)
     SSL_CTX *      ctx
     long	    op

LHASH *
SSL_CTX_sessions(ctx)
     SSL_CTX *          ctx
     CODE:
    /* NOTE: This should be deprecated. Corresponding macro was removed from ssl.h as of 0.9.2 */
     if (ctx == NULL) croak("NULL SSL context passed as argument.");
     RETVAL = ctx -> sessions;
     OUTPUT:
     RETVAL

unsigned long
SSL_CTX_sess_number(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_connect(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_connect_good(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_connect_renegotiate(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_accept(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_accept_renegotiate(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_accept_good(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_hits(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_cb_hits(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_misses(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_timeouts(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_cache_full(ctx)
     SSL_CTX *          ctx

int
SSL_CTX_sess_get_cache_size(ctx)
     SSL_CTX *          ctx

void
SSL_CTX_sess_set_cache_size(ctx,size)
     SSL_CTX *          ctx
     int                size      

int
SSL_want(s)
     SSL *              s

int
SSL_state(s)
     SSL *              s

BIO_METHOD *
BIO_f_ssl()

BIO_METHOD *
BIO_s_mem()

unsigned long
ERR_get_error()

unsigned long
ERR_peek_error()

void
ERR_put_error(lib,func,reason,file,line)
     int                lib
     int                func
     int                reason
     char *             file
     int                line

void
ERR_clear_error()

char *
ERR_error_string(error,buf=NULL)
     unsigned long      error
     char *             buf
     CODE:
     RETVAL = ERR_error_string(error,buf);
     OUTPUT:
     RETVAL

void
SSL_load_error_strings()

void
ERR_load_crypto_strings()

int
SSL_library_init()
	ALIAS:
		SSLeay_add_ssl_algorithms  = 1
		OpenSSL_add_ssl_algorithms = 2
		add_ssl_algorithms         = 3

void
ERR_load_SSL_strings()

void
ERR_load_RAND_strings()

int
RAND_bytes(buf, num)
    SV *buf
    int num
    PREINIT:
        int rc;
        unsigned char *random;
    CODE:
        New(0, random, num, unsigned char);
        rc = RAND_bytes(random, num);
        sv_setpvn(buf, (const char*)random, num);
        Safefree(random);
        RETVAL = rc;
    OUTPUT:
        RETVAL

int
RAND_pseudo_bytes(buf, num)
    SV *buf
    int num
    PREINIT:
        int rc;
        unsigned char *random;
    CODE:
        New(0, random, num, unsigned char);
        rc = RAND_pseudo_bytes(random, num);
        sv_setpvn(buf, (const char*)random, num);
        Safefree(random);
        RETVAL = rc;
    OUTPUT:
        RETVAL

void
RAND_add(buf, num, entropy)
    SV *buf
    int num
    double entropy
    PREINIT:
        STRLEN len;
    CODE:
        RAND_add((const void *)SvPV(buf, len), num, entropy);

int
RAND_poll()

int
RAND_status()

int
RAND_egd_bytes(path, bytes)
    const char *path
    int bytes

SV *
RAND_file_name(num)
    size_t num
    PREINIT:
        char *buf;
    CODE:
        New(0, buf, num, char);
        if (!RAND_file_name(buf, num)) {
            Safefree(buf);
            XSRETURN_UNDEF;
        }
        RETVAL = newSVpv(buf, 0);
        Safefree(buf);
    OUTPUT:
        RETVAL

void
RAND_seed(buf)
     PREINIT:
     STRLEN len;
     INPUT:
     char *  buf = SvPV( ST(1), len);
     CODE:
     RAND_seed (buf, (int)len);

void
RAND_cleanup()

int
RAND_load_file(file_name, how_much)
     char *  file_name
     int     how_much

int
RAND_write_file(file_name)
     char *  file_name

int
RAND_egd(path)
     char *  path

#define REM40 "Minimal X509 stuff..., this is a bit ugly and should be put in its own modules Net::SSLeay::X509.pm"

X509_NAME*
X509_get_issuer_name(cert)
     X509 *      cert

X509_NAME*
X509_get_subject_name(cert)
     X509 *      cert

void
X509_NAME_oneline(name)
	X509_NAME *    name
	PREINIT:
	char * buf;
	CODE:
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if (buf = X509_NAME_oneline(name, NULL, 0))
		sv_setpvn( ST(0), buf, strlen(buf));
	free(buf);

# WTF is the point of this function?
# The NID_* constants aren't bound anyway and no one can remember
# those undocumented numbers anyway.
void
X509_NAME_get_text_by_NID(name,nid)
	X509_NAME *    name
	int nid
	PREINIT:
	char* buf;
	int length;
	CODE:
	ST(0) = sv_newmortal();   /* Undefined to start with */
	length = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
	printf("length: %d\n", length);

	buf = (char*)malloc( sizeof(char) * (length + 1) );

	if (X509_NAME_get_text_by_NID(name, nid, buf, length + 1))
		sv_setpvn( ST(0), buf, length + 1);

X509 *
X509_STORE_CTX_get_current_cert(x509_store_ctx)
     X509_STORE_CTX * 	x509_store_ctx

void *
X509_STORE_CTX_get_ex_data(x509_store_ctx,idx)
     X509_STORE_CTX * x509_store_ctx
     int idx

void
X509_get_subjectAltNames(cert)
     X509 *      cert
     PPCODE:
     int                    i, j = 0;
     X509_EXTENSION         *subjAltNameExt = NULL;
     STACK_OF(GENERAL_NAME) *subjAltNameDNs = NULL;
     GENERAL_NAME           *subjAltNameDN  = NULL;
     int                    num_gnames;
     if (  (i = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1))
         && (subjAltNameExt = X509_get_ext(cert, i))
	 && (subjAltNameDNs = X509V3_EXT_d2i(subjAltNameExt)))
     {
         num_gnames = sk_GENERAL_NAME_num(subjAltNameDNs);
	 for (j = 0; j < num_gnames; j++) 
	 {
	    subjAltNameDN = sk_GENERAL_NAME_value(subjAltNameDNs, j);
	    XPUSHs(sv_2mortal(newSViv(subjAltNameDN->type)));
	    XPUSHs(sv_2mortal(newSVpv((const char*)ASN1_STRING_data(subjAltNameDN->d.ia5), ASN1_STRING_length(subjAltNameDN->d.ia5))));
	 }
     }
     XSRETURN(j*2);

int
X509_get_ext_by_NID(x,nid,loc)
	X509* x
	int nid
	int loc

X509_EXTENSION *
X509_get_ext(x,loc)
	X509* x
	int loc
	
void *
X509V3_EXT_d2i(ext)
	X509_EXTENSION *ext

int
X509_STORE_CTX_get_error(x509_store_ctx)
     X509_STORE_CTX * 	x509_store_ctx

int
X509_STORE_CTX_get_error_depth(x509_store_ctx)
     X509_STORE_CTX * 	x509_store_ctx

int
X509_STORE_CTX_set_ex_data(x509_store_ctx,idx,data)
     X509_STORE_CTX *   x509_store_ctx
     int idx
     void * data

void
X509_STORE_CTX_set_error(x509_store_ctx,s)
     X509_STORE_CTX * x509_store_ctx
     int s

void
X509_STORE_CTX_set_cert(x509_store_ctx,x)
     X509_STORE_CTX * x509_store_ctx
     X509 * x

int 
X509_STORE_add_cert(ctx, x)
    X509_STORE *ctx
    X509 *x

int 
X509_STORE_add_crl(ctx, x)
    X509_STORE *ctx
    X509_CRL *x

void 
X509_STORE_CTX_set_flags(ctx, flags)
    X509_STORE_CTX *ctx
    long flags

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL

void 
X509_STORE_set_flags(ctx, flags)
    X509_STORE *ctx
    long flags

void 
X509_STORE_set_purpose(ctx, purpose)
    X509_STORE *ctx
    int purpose

void 
X509_STORE_set_trust(ctx, trust)
    X509_STORE *ctx
    int trust

#endif

int 
X509_load_cert_file(ctx, file, type)
    X509_LOOKUP *ctx
    char *file
    int type

int 
X509_load_crl_file(ctx, file, type)
    X509_LOOKUP *ctx
    char *file
    int type

int 
X509_load_cert_crl_file(ctx, file, type)
    X509_LOOKUP *ctx
    char *file
    int type

const char *
X509_verify_cert_error_string(n)
    long n   


ASN1_UTCTIME *
X509_get_notBefore(cert)
     X509 *	cert

ASN1_UTCTIME *
X509_get_notAfter(cert)
     X509 *	cert

void 
P_ASN1_UTCTIME_put2string(tm)
     ASN1_UTCTIME *	tm
     PREINIT:
     BIO *bp;
     int i;
     char buffer[256];
     CODE:
     bp = BIO_new(BIO_s_mem());
     ASN1_UTCTIME_print(bp,tm);
     i = BIO_read(bp,buffer,255);
     buffer[i] = '\0';
     ST(0) = sv_newmortal();   /* Undefined to start with */
     if ( i > 0 )
         sv_setpvn( ST(0), buffer, i );
     BIO_free(bp);

int
EVP_PKEY_copy_parameters(to,from)
     EVP_PKEY *		to
     EVP_PKEY * 	from

void 
PEM_get_string_X509(x509)
     X509 *	x509
     PREINIT:
     BIO *bp;
     int i;
     char buffer[8196];
     CODE:
     bp = BIO_new(BIO_s_mem());
     PEM_write_bio_X509(bp,x509);
     i = BIO_read(bp,buffer,8195);
     buffer[i] = '\0';
     ST(0) = sv_newmortal();   /* Undefined to start with */
     if ( i > 0 )
         sv_setpvn( ST(0), buffer, i );
     BIO_free(bp);

void
MD2(data)
	PREINIT:
	STRLEN len;
	unsigned char md[MD2_DIGEST_LENGTH];
	unsigned char * ret;
	INPUT:
	unsigned char* data = (unsigned char *) SvPV( ST(0), len);
	CODE:
	ret = MD2(data,len,md);
	if (ret!=NULL) {
		XSRETURN_PVN((char *) md, MD2_DIGEST_LENGTH);
	} else {
		XSRETURN_UNDEF;
	}

void
MD4(data)
	PREINIT:
	STRLEN len;
	unsigned char md[MD4_DIGEST_LENGTH];
	unsigned char * ret;
	INPUT:
	unsigned char* data = (unsigned char *) SvPV( ST(0), len );
	CODE:
	ret = MD4(data,len,md);
	if (ret!=NULL) {
		XSRETURN_PVN((char *) md, MD4_DIGEST_LENGTH);
	} else {
		XSRETURN_UNDEF;
	}

void 
MD5(data)
     PREINIT:
     STRLEN len;
     unsigned char md[MD5_DIGEST_LENGTH];
     unsigned char * ret;
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     ret = MD5(data,len,md);
     if (ret!=NULL) {
	  XSRETURN_PVN((char *) md, MD5_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

SSL_METHOD *
SSLv2_method()

SSL_METHOD *
SSLv3_method()

SSL_METHOD *
TLSv1_method()

int
SSL_set_ssl_method(ssl, method)
     SSL *          ssl
     SSL_METHOD *   method

SSL_METHOD *
SSL_get_ssl_method(ssl)
     SSL *          ssl

#define REM_AUTOMATICALLY_GENERATED_1_09

BIO *
BIO_new_buffer_ssl_connect(ctx)
     SSL_CTX *	ctx

BIO *
BIO_new_file(filename,mode)
     char * filename
     char * mode

BIO *
BIO_new_ssl(ctx,client)
     SSL_CTX *	ctx
     int 	client

BIO *
BIO_new_ssl_connect(ctx)
     SSL_CTX *	ctx

BIO *
BIO_new(type)
     BIO_METHOD * type;

int
BIO_free(bio)
     BIO * bio;

void
BIO_read(s,max=32768)
	BIO *   s
	int max
	PREINIT:
	char *buf = NULL;
	int got;
	CODE:
	printf("max: %d\n", max);
	buf = (char*)malloc( sizeof(char) * max );
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = BIO_read(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	free(buf);

int
BIO_write(s,buf)
     BIO *   s
     PREINIT:
     STRLEN len;
     INPUT:
     char *  buf = SvPV( ST(1), len);
     CODE:
     RETVAL = BIO_write (s, buf, (int)len);
     OUTPUT:
     RETVAL

int
BIO_eof(s)
     BIO *   s

int
BIO_pending(s)
     BIO *   s

int
BIO_wpending(s)
     BIO *   s

int 
BIO_ssl_copy_session_id(to,from)
     BIO *	to
     BIO *	from

void 
BIO_ssl_shutdown(ssl_bio)
     BIO *	ssl_bio

int 
SSL_add_client_CA(ssl,x)
     SSL *	ssl
     X509 *	x

const char *
SSL_alert_desc_string(value)
     int 	value

const char *
SSL_alert_desc_string_long(value)
     int 	value

const char *
SSL_alert_type_string(value)
     int 	value

const char *
SSL_alert_type_string_long(value)
     int 	value

long	
SSL_callback_ctrl(ssl,i,fp)
     SSL *  ssl
     int    i
     callback_no_ret * fp

int 
SSL_check_private_key(ctx)
     SSL *	ctx

char *
SSL_CIPHER_description(cipher,buf,size)
     SSL_CIPHER *  cipher
     char *	buf
     int 	size

int	
SSL_CIPHER_get_bits(c,alg_bits)
     SSL_CIPHER *	c
     int *	alg_bits

int 
SSL_COMP_add_compression_method(id,cm)
     int 	id
     COMP_METHOD *	cm

int 
SSL_CTX_add_client_CA(ctx,x)
     SSL_CTX *	ctx
     X509 *	x

long	
SSL_CTX_callback_ctrl(ctx,i,fp)
     SSL_CTX *  ctx
     int        i
     callback_no_ret * fp

int 
SSL_CTX_check_private_key(ctx)
     SSL_CTX *	ctx

void *
SSL_CTX_get_ex_data(ssl,idx)
     SSL_CTX *	ssl
     int 	idx

int 
SSL_CTX_get_quiet_shutdown(ctx)
     SSL_CTX *	ctx

long 
SSL_CTX_get_timeout(ctx)
     SSL_CTX *	ctx

int 
SSL_CTX_get_verify_depth(ctx)
     SSL_CTX *	ctx

int 
SSL_CTX_get_verify_mode(ctx)
     SSL_CTX *	ctx

void 
SSL_CTX_set_cert_store(ctx,store)
     SSL_CTX *     ctx
     X509_STORE *  store

X509_STORE *
SSL_CTX_get_cert_store(ctx)
     SSL_CTX *     ctx

void 
SSL_CTX_set_cert_verify_callback(ctx,cb,arg)
     SSL_CTX *	ctx
     callback_ret_int *  cb
     char *	arg

void 
SSL_CTX_set_client_CA_list(ctx,list)
     SSL_CTX *	ctx
     X509_NAME_STACK * list

void 
SSL_CTX_set_default_passwd_cb(ctx,func=NULL)
	SSL_CTX *	ctx
	SV * func
	PREINIT:
	ssleay_ctx_passwd_cb_t* cb;
	CODE:
	if (func == NULL || func == &PL_sv_undef) {
		ssleay_ctx_passwd_cb_free(ctx);
		SSL_CTX_set_default_passwd_cb(ctx, NULL);
	} else {
		cb = ssleay_ctx_passwd_cb_get(ctx);
		ssleay_ctx_passwd_cb_func_set(ctx, func);
		SSL_CTX_set_default_passwd_cb(ctx, &ssleay_ctx_passwd_cb_invoke);
		SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)cb);
	}

void 
SSL_CTX_set_default_passwd_cb_userdata(ctx,u=NULL)
	SSL_CTX *	ctx
	SV*	u
	CODE:
		ssleay_ctx_passwd_cb_userdata_set(ctx, u);

int 
SSL_CTX_set_ex_data(ssl,idx,data)
     SSL_CTX *	ssl
     int 	idx
     void *	data

int 
SSL_CTX_set_purpose(s,purpose)
     SSL_CTX *	s
     int 	purpose

void 
SSL_CTX_set_quiet_shutdown(ctx,mode)
     SSL_CTX *	ctx
     int 	mode

int 
SSL_CTX_set_ssl_version(ctx,meth)
     SSL_CTX *	ctx
     SSL_METHOD *	meth

long 
SSL_CTX_set_timeout(ctx,t)
     SSL_CTX *	ctx
     long 	t

int 
SSL_CTX_set_trust(s,trust)
     SSL_CTX *	s
     int 	trust

void 
SSL_CTX_set_verify_depth(ctx,depth)
     SSL_CTX *	ctx
     int 	depth

int 
SSL_CTX_use_certificate(ctx,x)
     SSL_CTX *	ctx
     X509 *	x

int	
SSL_CTX_use_certificate_chain_file(ctx,file)
     SSL_CTX *	ctx
     const char * file

int 
SSL_CTX_use_PrivateKey(ctx,pkey)
     SSL_CTX *	ctx
     EVP_PKEY *	pkey

int 
SSL_CTX_use_RSAPrivateKey(ctx,rsa)
     SSL_CTX *	ctx
     RSA *	rsa

int 
SSL_do_handshake(s)
     SSL *	s

SSL *
SSL_dup(ssl)
     SSL *	ssl

SSL_CIPHER *
SSL_get_current_cipher(s)
     SSL *	s

long 
SSL_get_default_timeout(s)
     SSL *	s

void *
SSL_get_ex_data(ssl,idx)
     SSL *	ssl
     int 	idx

size_t 
SSL_get_finished(s,buf,count)
     SSL *	s
     void *	buf
     size_t 	count

size_t 
SSL_get_peer_finished(s,buf,count)
     SSL *	s
     void *	buf
     size_t 	count

int 
SSL_get_quiet_shutdown(ssl)
     SSL *	ssl

int 
SSL_get_shutdown(ssl)
     SSL *	ssl

int	
SSL_get_verify_depth(s)
     SSL *	s

int	
SSL_get_verify_mode(s)
     SSL *	s

long 
SSL_get_verify_result(ssl)
     SSL *	ssl

int 
SSL_renegotiate(s)
     SSL *	s

int	
SSL_SESSION_cmp(a,b)
     SSL_SESSION *	a
     SSL_SESSION *	b

void *
SSL_SESSION_get_ex_data(ss,idx)
     SSL_SESSION *	ss
     int 	idx

long	
SSL_SESSION_get_time(s)
     SSL_SESSION *	s

long	
SSL_SESSION_get_timeout(s)
     SSL_SESSION *	s

int	
SSL_SESSION_print_fp(fp,ses)
     FILE *	fp
     SSL_SESSION *	ses

int 
SSL_SESSION_set_ex_data(ss,idx,data)
     SSL_SESSION *	ss
     int 	idx
     void *	data

long	
SSL_SESSION_set_time(s,t)
     SSL_SESSION *	s
     long 	t

long	
SSL_SESSION_set_timeout(s,t)
     SSL_SESSION *	s
     long 	t

void 
SSL_set_accept_state(s)
     SSL *	s

void 
SSL_set_client_CA_list(s,list)
     SSL *	s
     X509_NAME_STACK *  list

void 
SSL_set_connect_state(s)
     SSL *	s

int 
SSL_set_ex_data(ssl,idx,data)
     SSL *	ssl
     int 	idx
     void *	data

void 
SSL_set_info_callback(ssl,cb)
     SSL *	ssl
     callback_no_ret *  cb

int 
SSL_set_purpose(s,purpose)
     SSL *	s
     int 	purpose

void 
SSL_set_quiet_shutdown(ssl,mode)
     SSL *	ssl
     int 	mode

void 
SSL_set_shutdown(ssl,mode)
     SSL *	ssl
     int 	mode

int 
SSL_set_trust(s,trust)
     SSL *	s
     int 	trust

void
SSL_set_verify_depth(s,depth)
     SSL *	s
     int 	depth

void 
SSL_set_verify_result(ssl,v)
     SSL *	ssl
     long 	v

int 
SSL_shutdown(s)
     SSL *	s

int 
SSL_version(ssl)
     SSL *	ssl

#define REM_MANUALLY_ADDED_1_09

X509_NAME_STACK *
SSL_load_client_CA_file(file)
     const char * file

int	
SSL_add_file_cert_subjects_to_stack(stackCAs,file)
     X509_NAME_STACK * stackCAs
     const char * file

#ifndef WIN32
#ifndef VMS
#ifndef MAC_OS_pre_X

int
SSL_add_dir_cert_subjects_to_stack(stackCAs,dir)
     X509_NAME_STACK * stackCAs
     const char * dir

#endif
#endif
#endif

int
SSL_CTX_get_ex_new_index(argl,argp,new_func,dup_func,free_func)
     long argl
     void *  argp
     CRYPTO_EX_new *   new_func
     CRYPTO_EX_dup *   dup_func
     CRYPTO_EX_free *  free_func

int
SSL_CTX_set_session_id_context(ctx,sid_ctx,sid_ctx_len)
     SSL_CTX *   ctx
     const unsigned char *   sid_ctx
     unsigned int sid_ctx_len

int
SSL_set_session_id_context(ssl,sid_ctx,sid_ctx_len)
     SSL *   ssl
     const unsigned char *   sid_ctx
     unsigned int sid_ctx_len

void
SSL_CTX_set_tmp_rsa_callback(ctx, cb)
     SSL_CTX *   ctx
     cb_ssl_int_int_ret_RSA *   cb

void
SSL_set_tmp_rsa_callback(ssl, cb)
     SSL *   ssl
     cb_ssl_int_int_ret_RSA *  cb

void
SSL_CTX_set_tmp_dh_callback(ctx, dh)
     SSL_CTX *   ctx
     cb_ssl_int_int_ret_DH *  dh

void
SSL_set_tmp_dh_callback(ssl,dh)
     SSL *  ssl
     cb_ssl_int_int_ret_DH *  dh

int
SSL_get_ex_new_index(argl, argp, new_func, dup_func, free_func)
     long argl
     void *   argp
     CRYPTO_EX_new *  new_func
     CRYPTO_EX_dup *  dup_func
     CRYPTO_EX_free * free_func

int
SSL_SESSION_get_ex_new_index(argl, argp, new_func, dup_func, free_func)
     long argl
     void *   argp
     CRYPTO_EX_new *  new_func
     CRYPTO_EX_dup *  dup_func
     CRYPTO_EX_free * free_func

#define REM_SEMIAUTOMATIC_MACRO_GEN_1_09

long
SSL_clear_num_renegotiations(ssl)
  SSL *  ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_add_extra_chain_cert(ctx,x509)
     SSL_CTX *	ctx
     X509 *     x509
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char*)x509);
  OUTPUT:
  RETVAL

void *
SSL_CTX_get_app_data(ctx)
     SSL_CTX *	ctx
  CODE:
  RETVAL = SSL_CTX_get_ex_data(ctx,0);
  OUTPUT:
  RETVAL

long	
SSL_CTX_get_mode(ctx)
     SSL_CTX *	ctx
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_MODE,0,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_get_read_ahead(ctx)
     SSL_CTX *	ctx
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_get_session_cache_mode(ctx)
     SSL_CTX *	ctx
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_need_tmp_RSA(ctx)
     SSL_CTX *	ctx
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_NEED_TMP_RSA,0,NULL);
  OUTPUT:
  RETVAL

int 
SSL_CTX_set_app_data(ctx,arg)
     SSL_CTX *	ctx
     char *	arg
  CODE:
  RETVAL = SSL_CTX_set_ex_data(ctx,0,arg);
  OUTPUT:
  RETVAL

long	
SSL_CTX_set_mode(ctx,op)
     SSL_CTX *	ctx
     long 	op
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_MODE,op,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_set_read_ahead(ctx,m)
     SSL_CTX *	ctx
     long 	m
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_set_session_cache_mode(ctx,m)
     SSL_CTX *	ctx
     long 	m
  CODE:
  RETVAL = SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL);
  OUTPUT:
  RETVAL

long	
SSL_CTX_set_tmp_dh(ctx,dh)
     SSL_CTX *	ctx
     DH *	dh

long	
SSL_CTX_set_tmp_rsa(ctx,rsa)
     SSL_CTX *	ctx
     RSA *	rsa

void *
SSL_get_app_data(s)
     SSL *	s
  CODE:
  RETVAL = SSL_get_ex_data(s,0);
  OUTPUT:
  RETVAL

int	
SSL_get_cipher_bits(s,np)
     SSL *	s
     int *	np
  CODE:
  RETVAL = SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np);
  OUTPUT:
  RETVAL

long	
SSL_get_mode(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_MODE,0,NULL);
  OUTPUT:
  RETVAL

int 
SSL_get_state(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_state(ssl);
  OUTPUT:
  RETVAL

long	
SSL_need_tmp_RSA(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_NEED_TMP_RSA,0,NULL);
  OUTPUT:
  RETVAL

long	
SSL_num_renegotiations(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL);
  OUTPUT:
  RETVAL

void *
SSL_SESSION_get_app_data(ses)
     SSL_SESSION *	ses
  CODE:
  RETVAL = SSL_SESSION_get_ex_data(ses,0);
  OUTPUT:
  RETVAL

long	
SSL_session_reused(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_GET_SESSION_REUSED,0,NULL);
  OUTPUT:
  RETVAL

int 
SSL_SESSION_set_app_data(s,a)
     SSL_SESSION *	s
     void *	a
  CODE:
  RETVAL = SSL_SESSION_set_ex_data(s,0,(char *)a);
  OUTPUT:
  RETVAL

int 
SSL_set_app_data(s,arg)
     SSL *	s
     void *	arg
  CODE:
  RETVAL = SSL_set_ex_data(s,0,(char *)arg);
  OUTPUT:
  RETVAL

long	
SSL_set_mode(ssl,op)
     SSL *	ssl
     long 	op
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_MODE,op,NULL);
  OUTPUT:
  RETVAL

int	
SSL_set_pref_cipher(s,n)
     SSL *	s
     const char * n
  CODE:
  RETVAL = SSL_set_cipher_list(s,n);
  OUTPUT:
  RETVAL

long	
SSL_set_tmp_dh(ssl,dh)
     SSL *	ssl
     char *	dh
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)dh);
  OUTPUT:
  RETVAL

long	
SSL_set_tmp_rsa(ssl,rsa)
     SSL *	ssl
     char *	rsa
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_SET_TMP_RSA,0,(char *)rsa);
  OUTPUT:
  RETVAL

RSA *
RSA_generate_key(bits,e,callback=NULL,cb_arg=NULL)
    int           bits
    unsigned long e
    generate_key_cb *        callback
    void *        cb_arg

void
RSA_free(r)
    RSA * r

void
X509_free(a)
    X509 * a

DH *
PEM_read_bio_DHparams(bio,x=NULL,cb=NULL,u=NULL)
	BIO  * bio
	void * x
	pem_password_cb * cb
	void * u

X509_CRL *
PEM_read_bio_X509_CRL(bio,x=NULL,cb=NULL,u=NULL)
	BIO  * bio
	void * x
	pem_password_cb * cb
	void * u

void
DH_free(dh)
	DH * dh

long
SSL_total_renegotiations(ssl)
     SSL *	ssl
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL);
  OUTPUT:
  RETVAL

void
SSL_SESSION_get_master_key(s)
     SSL_SESSION *   s
     CODE:
     ST(0) = sv_newmortal();   /* Undefined to start with */
     sv_setpvn(ST(0), (const char*)s->master_key, s->master_key_length);

void
SSL_get_client_random(s)
     SSL *   s
     CODE:
     ST(0) = sv_newmortal();   /* Undefined to start with */
     sv_setpvn(ST(0), (const char*)s->s3->client_random, SSL3_RANDOM_SIZE);

void
SSL_get_server_random(s)
     SSL *   s
     CODE:
     ST(0) = sv_newmortal();   /* Undefined to start with */
     sv_setpvn(ST(0), (const char*)s->s3->server_random, SSL3_RANDOM_SIZE);


#define REM_EOF "/* EOF - SSLeay.xs */"
