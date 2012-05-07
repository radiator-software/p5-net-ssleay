/* SSLeay.xs - Perl module for using Eric Young's implementation of SSL
 *
 * Copyright (c) 1996-2002 Sampo Kellomaki <sampo@iki.fi>
 * Copyright (C) 2005 Florian Ragwitz <rafl@debian.org>
 * Copyright (C) 2005 Mike McCauley <mikem@open.com.au>
 * 
 * All Rights Reserved.
 *
 * Change data removed. See Changes
 *
 * $Id$
 * 
 * The distribution and use of this module are subject to the conditions
 * listed in LICENSE file at the root of OpenSSL-0.9.6b
 * distribution (i.e. free, but mandatory attribution and NO WARRANTY).
 */

/* ####
 * #### PLEASE READ THE FOLLOWING RULES BEFORE YOU START EDITING THIS FILE! ####
 * ####
 *
 * Function naming conventions:
 *
 * 1/ never change the aready existing function names (all calling convention) in a way
 *    that may cause backward incompatibility (e.g. add ALIAS with old name if necessary)
 *
 * 2/ it is recommended to keep the original openssl function names for functions that are:
 *
 *    1:1 wrappers to the original openssl functions
 *    see for example: X509_get_issuer_name(cert) >> Net::SSLeay::X509_get_issuer_name($cert)
 *
 *    nearly 1:1 wrappers implementing only necessary "glue" e.g. buffer handling
 *    see for example: RAND_seed(buf,len) >> Net::SSLeay::RAND_seed($buf)
 *
 * 3/ OpenSSL functions starting with "SSL_" are added into SSLeay.xs with "SLL_" prefix
 *    (e.g. SSL_CTX_new) but keep in mind that they will be available in Net::SSLeay without
 *    "SSL_" prefix (e.g. Net::SSLeay::CTX_new) - keep this for all new functions
 *
 * 4/ The names of functions which do not fit rule 2/ (which means they implement some non
 *    trivial code around original openssl function or do more complex tasks) should be
 *    prefixed with "P_" - see for example: P_ASN1_TIME_set_isotime
 *
 * 5/ Exceptions from rules above:
 *    functions that are part or wider set of already existing function not following this rule
 *    for example: there already exists: PEM_get_string_X509_CRL + PEM_get_string_X509_REQ and you want
 *    to add PEM_get_string_SOMETHING - then no need to follow 3/ (do not prefix with "P_")
 *
 * Support for different openssl versions, different platforms, different compilers:
 *
 * 1/ SSleay.xs is expected to build/pass test suite
 *    - with openssl 0.9.6 and newer versions
 *    - with perl 5.8 and newer versions
 *
 * 2/ Fix all compiler warnings - we expect 100% clean build
 *
 * 3/ If you are gonna add a function which is available since certain openssl version
 *    use proper #ifdefs to assure that SSLeay.xs will compile also with older versions
 *    which are missing this function
 *
 * 4/ Even warnings arising from different use of "const" in different openssl versions
 *    needs to be hanled with #ifdefs - see for example: X509_NAME_add_entry_by_txt
 *
 * 5/ avoid using global C variables (it is very likely gonna break thread-safetyness)
 *    use rather global MY_CXT structure
 *
 * 6/ avoid using any UNIX/POSIX specific functions, keep in mind that SSLeay.xs must
 *    complile also on non-UNIX platforms like MS Windows and others
 *
 * 7/ avoid using c++ comments "//" (or other c++ features accepted by some c compiler)
 *    even if your compiler can handle them without warnings
 *
 * Passing test suite:
 *
 * 1/ any changes to SSLeay.xs must not introduce a failure of existing test suite
 *
 * 2/ it is strongly recommended to create test(s) for newly added function(s), especially
 *    when the new function is not only a 1:1 wrapper but contains a complex code
 *
 * 3/ it is mandatory to add a dcumentation for all newly added functions into SSLeay.pod
 *    otherwise t/local/02_pod_coverage.t is gonna fail (and you will be asked to add
 *    some doc into your patch)
 *
 * Prefered code layout:
 *
 * 1/ for simple 1:1 XS wrappers use:
 *
 *    a/ functions whith short "signarute" (short list of args):
 *
 *    long
 *    SSL_set_tmp_dh(SSL *ssl,DH *dh)
 *
 *    b/ functions whith long "signarute" (long list of args):
 *       simply when approach a/ does not fit to 120 columns
 *
 *    void
 *    SSL_any_functions(library_flag,function_name,reason,file_name,line)
 *            int library_flag
 *            int function_name
 *            int reason
 *            char *file_name
 *            int line
 *
 * 2/ for XS functions with full implementation use identation like this:
 *
 *    int
 *    RAND_bytes(buf, num)
 *            SV *buf
 *            int num
 *        PREINIT:
 *            int rc;
 *            unsigned char *random;
 *        CODE:
 *            / * some code here * /
 *            RETVAL = rc;
 *        OUTPUT:
 *            RETVAL
 *
 * THE LAST RULE:
 *
 * The fact that some parts of SSLeay.xs do not follow the rules above is not 
 * a reason why any new code can also break these rules in the same way
 *
 */

/* Prevent warnings about strncpy from Windows compilers */
#define _CRT_SECURE_NO_DEPRECATE

#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_newRV_noinc
#define NEED_sv_2pv_flags
#define NEED_my_snprintf
#include "ppport.h"
#ifdef __cplusplus
}
#endif

/* OpenSSL-0.9.3a has some strange warning about this in
 *    openssl/des.h
 */
#undef _

/* Sigh: openssl 1.0 has
 typedef void *BLOCK;
which conflicts with perls
 typedef struct block BLOCK;
*/
#define BLOCK OPENSSL_BLOCK
#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/comp.h>    /* openssl-0.9.6a forgets to include this */
#ifndef OPENSSL_NO_MD2
#include <openssl/md2.h>
#endif
#include <openssl/md4.h>
#include <openssl/md5.h>     /* openssl-SNAP-20020227 does not automatically include this */
#if OPENSSL_VERSION_NUMBER >= 0x00905000L
#include <openssl/ripemd.h>
#endif
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
/* requires 0.9.7+ */
#include <openssl/engine.h>
#endif
#undef BLOCK

/* Debugging output - to enable use:
 *
 * perl Makefile.PL DEFINE=-DSHOW_XS_DEBUG
 * make
 *
 */

#ifdef SHOW_XS_DEBUG
#define PR1(s) fprintf(stderr,s);
#define PR2(s,t) fprintf(stderr,s,t);
#define PR3(s,t,u) fprintf(stderr,s,t,u);
#define PR4(s,t,u,v) fprintf(stderr,s,t,u,v);
#else
#define PR1(s)
#define PR2(s,t)
#define PR3(s,t,u)
#define PR4(s,t,u,v)
#endif

#include "constants.c"

/* ============= thread-safety related stuff ============== */

#define MY_CXT_KEY "Net::SSLeay::_guts" XS_VERSION

typedef struct {
    HV* global_cb_data;
    UV tid;
} my_cxt_t;
START_MY_CXT;

#ifdef USE_ITHREADS
static perl_mutex LIB_init_mutex;
static perl_mutex *GLOBAL_openssl_mutex = NULL;
#endif
static int LIB_initialized;

UV get_my_thread_id(void) /* returns threads->tid() value */
{
    dSP;
    UV tid;
    int count = 0;

#ifdef USE_ITHREADS
    ENTER;
    SAVETMPS;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVpv("threads", 0)));
    PUTBACK;
    count = call_method("tid", G_SCALAR|G_EVAL);
    SPAGAIN;
    if (SvTRUE(ERRSV) || count != 1)
       /* if threads not loaded or an error occurs return 0 */
       tid = 0;
    else
       tid = (UV)POPi;
    PUTBACK;
    FREETMPS;
    LEAVE;
#endif

    return tid;
}

/* IMPORTANT NOTE:
 * openssl locking was implemented according to http://www.openssl.org/docs/crypto/threads.html
 * we implement both static and dynamic locking as described on URL above
 * locking is supported when OPENSSL_THREADS macro is defined which means openssl-0.9.7 or newer
 * we intentionally do not implement cleanup of openssl's threading as it causes troubles
 * with apache-mpm-worker+mod_perl+mod_ssl+net-ssleay
 */
#if defined(USE_ITHREADS) && defined(OPENSSL_THREADS)

static void openssl_locking_function(int mode, int type, const char *file, int line)
{
    if (!GLOBAL_openssl_mutex) return;
    if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(&GLOBAL_openssl_mutex[type]);
    else
      MUTEX_UNLOCK(&GLOBAL_openssl_mutex[type]);
}

#if OPENSSL_VERSION_NUMBER < 0x10000000L
static unsigned long openssl_threadid_func(void)
{
    dMY_CXT;
    return (unsigned long)(MY_CXT.tid);
}
#else
void openssl_threadid_func(CRYPTO_THREADID *id)
{
    dMY_CXT;
    CRYPTO_THREADID_set_numeric(id, (unsigned long)(MY_CXT.tid));
}
#endif

struct CRYPTO_dynlock_value
{
    perl_mutex mutex;
};

struct CRYPTO_dynlock_value * openssl_dynlocking_create_function (const char *file, int line)
{
    struct CRYPTO_dynlock_value *retval;
    New(0, retval, 1, struct CRYPTO_dynlock_value);
    if (!retval) return NULL;
    MUTEX_INIT(&retval->mutex);
    return retval;
}

void openssl_dynlocking_lock_function (int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)
{
    if (!l) return;
    if (mode & CRYPTO_LOCK)
      MUTEX_LOCK(&l->mutex);
    else
      MUTEX_UNLOCK(&l->mutex);
}

void openssl_dynlocking_destroy_function (struct CRYPTO_dynlock_value *l, const char *file, int line)
{
    if (!l) return;
    MUTEX_DESTROY(&l->mutex);
    Safefree(l);
}

void openssl_threads_init(void)
{
    int i;

    PR1("STARTED: openssl_threads_init\n");

    /* initialize static locking */
    if ( !CRYPTO_get_locking_callback() ) {
#if OPENSSL_VERSION_NUMBER < 0x10000000L
        if ( !CRYPTO_get_id_callback() ) {
#else
        if ( !CRYPTO_THREADID_get_callback() ) {
#endif
            PR1("openssl_threads_init static locking\n");
            New(0, GLOBAL_openssl_mutex, CRYPTO_num_locks(), perl_mutex);
            if (!GLOBAL_openssl_mutex) return;
            for (i=0; i<CRYPTO_num_locks(); i++) MUTEX_INIT(&GLOBAL_openssl_mutex[i]);
            CRYPTO_set_locking_callback((void (*)(int,int,const char *,int))openssl_locking_function);

#ifndef WIN32
            /* no need for threadid_func() on Win32 */
#if OPENSSL_VERSION_NUMBER < 0x10000000L
            CRYPTO_set_id_callback(openssl_threadid_func);
#else
            CRYPTO_THREADID_set_callback(openssl_threadid_func);
#endif
#endif
        }
    }

    /* initialize dynamic locking */
    if ( !CRYPTO_get_dynlock_create_callback() &&
         !CRYPTO_get_dynlock_lock_callback() &&
         !CRYPTO_get_dynlock_destroy_callback() ) {
        PR1("openssl_threads_init dynamic locking\n");
        CRYPTO_set_dynlock_create_callback(openssl_dynlocking_create_function);
        CRYPTO_set_dynlock_lock_callback(openssl_dynlocking_lock_function);
        CRYPTO_set_dynlock_destroy_callback(openssl_dynlocking_destroy_function);
    }
}

#endif

/* ============= typedefs to agument TYPEMAP ============== */

typedef void callback_no_ret(void);
typedef void cb_ssl_int_int_ret_void(const SSL *ssl,int,int);
typedef RSA * cb_ssl_int_int_ret_RSA(SSL * ssl,int is_export, int keylength);
typedef DH * cb_ssl_int_int_ret_DH(SSL * ssl,int is_export, int keylength);

typedef STACK_OF(X509_NAME) X509_NAME_STACK;

typedef int perl_filehandle_t;

/* ======= special handler used by EVP_MD_do_all_sorted ======= */

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL
static void handler_list_md_fn(const EVP_MD *m, const char *from, const char *to, void *arg)
{
  /* taken from apps/dgst.c */
  const char *mname;
  if (!m) return;                                           /* Skip aliases */
  mname = OBJ_nid2ln(EVP_MD_type(m));
  if (strcmp(from, mname)) return;                          /* Skip shortnames */
  if (EVP_MD_flags(m) & EVP_MD_FLAG_PKEY_DIGEST) return;    /* Skip clones */
  if (strchr(mname, ' ')) mname= EVP_MD_name(m);
  av_push(arg, newSVpv(mname,0));
}
#endif

/* ============= callbacks - basic info =============
 *
 * PLEASE READ THIS BEFORE YOU ADD ANY NEW CALLBACK!!
 *
 * There are basically 2 types of callbacks used in SSLeay:
 *
 * 1/ "one-time" callbacks - these are created+used+destroyed within one perl function implemented in XS
 *    these callbacks use a cpecial C structupe simple_cb_data_t to pass necessary data
 *    there are 2 related helper functions: simple_cb_data_new() + simple_cb_data_free
 *    for example see implementation of these functions:
 *    - RSA_generate_key
 *    - PEM_read_bio_PrivateKey
 *
 * 2/ "advanced" callbacks - these are setup/destroyed by one function but used by another function; these
 *    callbacks use global hash MY_CXT.global_cb_data to store perl functions + data to be uset at callback time
 *    there are 2 related helper functions: cb_data_advanced_put() + cb_data_advanced_get for manipulating
 *    global hash MY_CXT.global_cb_data which work like this:
 *        cb_data_advanced_put(<pointer>, "data_name", dataSV)
 *        >>>
 *        global_cb_data->{"ptr_<pointer>"}->{"data_name"} = dataSV)
 *    or
 *        data = cb_data_advanced_get(<pointer>, "data_name")
 *        >>>
 *        my $data = global_cb_data->{"ptr_<pointer>"}->{"data_name"}
 *    for example see implementation of these functions:
 *    - SSL_CTX_set_verify
 *    - SSL_set_verify
 *    - SSL_CTX_set_cert_verify_callback
 *    - SSL_CTX_set_default_passwd_cb
 *    - SSL_CTX_set_default_passwd_cb_userdata
 *    - SSL_set_session_secret_cb
 *
 * If wanna add a new callback:
 * - you vely likely need a new function "your_callback_name_invoke()"
 * - decide whether your case fits case 1/ or 2/ (and implement likewise existing functions)
 * - try to avoid adding a new style of callback implementation (or ask Net::SSLeay maintainers before)
 *
 */

/* ============= callback stuff - generic functions============== */

struct _ssleay_cb_t {
    SV* func;
    SV* data;
};
typedef struct _ssleay_cb_t simple_cb_data_t;

simple_cb_data_t* simple_cb_data_new(SV* func, SV* data)
{
    simple_cb_data_t* cb;
    New(0, cb, 1, simple_cb_data_t);
    if (cb) {
        SvREFCNT_inc(func);
        SvREFCNT_inc(data);
        cb->func = func;
        cb->data = data;
    }
    return cb;
}

void simple_cb_data_free(simple_cb_data_t* cb)
{
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
    Safefree(cb);
}

int cb_data_advanced_put(void *ptr, const char* data_name, SV* data)
{
    HV * L2HV;
    SV ** svtmp;
    int len;
    char key_name[500];
    dMY_CXT;

    len = my_snprintf(key_name, sizeof(key_name), "ptr_%p", ptr);
    if (len == sizeof(key_name)) return 0; /* error  - key_name too short*/

    /* get or create level-2 hash */
    svtmp = hv_fetch(MY_CXT.global_cb_data, key_name, strlen(key_name), 0);
    if (svtmp == NULL) {
        L2HV = newHV();
        hv_store(MY_CXT.global_cb_data, key_name, strlen(key_name), newRV_noinc((SV*)L2HV), 0);
    }
    else {
        if (!SvOK(*svtmp) || !SvROK(*svtmp)) return 0;
#if defined(MUTABLE_PTR)
        L2HV = (HV*)MUTABLE_PTR(SvRV(*svtmp));
#else
        L2HV = (HV*)(SvRV(*svtmp));
#endif
    }

    /* first delete already stored value */
    hv_delete(L2HV, data_name, strlen(data_name), G_DISCARD);
    if (data!=NULL)
        if (SvOK(data))
            hv_store(L2HV, data_name, strlen(data_name), data, 0);

    return 1;
}

SV* cb_data_advanced_get(void *ptr, const char* data_name)
{
    HV * L2HV;
    SV ** svtmp;
    int len;
    char key_name[500];
    dMY_CXT;

    len = my_snprintf(key_name, sizeof(key_name), "ptr_%p", ptr);
    if (len == sizeof(key_name)) return &PL_sv_undef; /* return undef on error - key_name too short*/

    /* get level-2 hash */
    svtmp = hv_fetch(MY_CXT.global_cb_data, key_name, strlen(key_name), 0);
    if (svtmp == NULL)  return &PL_sv_undef;
    if (!SvOK(*svtmp))  return &PL_sv_undef;
    if (!SvROK(*svtmp)) return &PL_sv_undef;
#if defined(MUTABLE_PTR)
    L2HV = (HV*)MUTABLE_PTR(SvRV(*svtmp));
#else
    L2HV = (HV*)(SvRV(*svtmp));
#endif

    /* get stored data */
    svtmp = hv_fetch(L2HV, data_name, strlen(data_name), 0);
    if (svtmp == NULL) return &PL_sv_undef;
    if (!SvOK(*svtmp)) return &PL_sv_undef;

    return *svtmp;
}

int cb_data_advanced_drop(void *ptr)
{
    int len;
    char key_name[500];
    dMY_CXT;

    len = my_snprintf(key_name, sizeof(key_name), "ptr_%p", ptr);
    if (len == sizeof(key_name)) return 0; /* error  - key_name too short*/

    hv_delete(MY_CXT.global_cb_data, key_name, strlen(key_name), G_DISCARD);
    return 1;
}

/* ============= callback stuff - invoke functions ============== */

static int ssleay_verify_callback_invoke (int ok, X509_STORE_CTX* x509_store)
{
    dSP;
    SSL* ssl;
    int count = -1, res;
    SV *cb_func;

    PR1("STARTED: ssleay_verify_callback_invoke\n");
    ssl = X509_STORE_CTX_get_ex_data(x509_store, SSL_get_ex_data_X509_STORE_CTX_idx());
    cb_func = cb_data_advanced_get(ssl, "ssleay_verify_callback!!func");
    
    if (!SvOK(cb_func)) {
        SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl);
        cb_func = cb_data_advanced_get(ssl_ctx, "ssleay_verify_callback!!func");
     }
 
    if (!SvOK(cb_func))
        croak("Net::SSLeay: verify_callback called, but not set to point to any perl function.\n");

    ENTER;
    SAVETMPS;

    PR2("verify callback glue ok=%d\n", ok);

    PUSHMARK(sp);
    EXTEND( sp, 2 );
    PUSHs( sv_2mortal(newSViv(ok)) );
    PUSHs( sv_2mortal(newSViv(PTR2IV(x509_store))) );
    PUTBACK;

    PR1("About to call verify callback.\n");
    count = call_sv(cb_func, G_SCALAR);
    PR1("Returned from verify callback.\n");

    SPAGAIN;

    if (count != 1)
        croak ( "Net::SSLeay: verify_callback perl function did not return a scalar.\n");

    res = POPi;

    PUTBACK;
    FREETMPS;
    LEAVE;

    return res;
}

static int ssleay_ctx_passwd_cb_invoke(char *buf, int size, int rwflag, void *userdata)
{
    dSP;
    int count = -1;
    char *res;
    SV *cb_func, *cb_data;

    PR1("STARTED: ssleay_ctx_passwd_cb_invoke\n");
    cb_func = cb_data_advanced_get(userdata, "ssleay_ctx_passwd_cb!!func");
    cb_data = cb_data_advanced_get(userdata, "ssleay_ctx_passwd_cb!!data");

    if(!SvOK(cb_func))
        croak ("Net::SSLeay: ssleay_ctx_passwd_cb_invoke called, but not set to point to any perl function.\n");

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);
    XPUSHs(sv_2mortal(newSViv(rwflag)));
    XPUSHs(sv_2mortal(newSVsv(cb_data)));
    PUTBACK;

    count = call_sv( cb_func, G_SCALAR );

    SPAGAIN;

    if (count != 1)
        croak("Net::SSLeay: ssleay_ctx_passwd_cb_invoke perl function did not return a scalar.\n");

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

int ssleay_ctx_cert_verify_cb_invoke(X509_STORE_CTX* x509_store_ctx, void* data)
{
    dSP;
    int count = -1;
    int res;
    SV * cb_func, *cb_data;
    void *ptr;
    SSL *ssl;

    PR1("STARTED: ssleay_ctx_cert_verify_cb_invoke\n");
#if OPENSSL_VERSION_NUMBER < 0x0090700fL
    ssl = X509_STORE_CTX_get_ex_data(x509_store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    ptr = (void*) SSL_get_SSL_CTX(ssl);
#else
    ssl = NULL;
    ptr = (void*) data;
#endif

    cb_func = cb_data_advanced_get(ptr, "ssleay_ctx_cert_verify_cb!!func");
    cb_data = cb_data_advanced_get(ptr, "ssleay_ctx_cert_verify_cb!!data");

    if(!SvOK(cb_func))
        croak ("Net::SSLeay: ssleay_ctx_cert_verify_cb_invoke called, but not set to point to any perl function.\n");

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSViv(PTR2IV(x509_store_ctx))));
    XPUSHs(sv_2mortal(newSVsv(cb_data)));
    PUTBACK;

    count = call_sv(cb_func, G_SCALAR);

    SPAGAIN;

    if (count != 1)
        croak("Net::SSLeay: ssleay_ctx_cert_verify_cb_invoke perl function did not return a scalar.\n");

    res = POPi;

    PUTBACK;
    FREETMPS;
    LEAVE;

    return res;
}

#if defined(SSL_F_SSL_SET_HELLO_EXTENSION) || defined(SSL_F_SSL_SET_SESSION_TICKET_EXT)

int ssleay_session_secret_cb_invoke(SSL* s, void* secret, int *secret_len,
                                    STACK_OF(SSL_CIPHER) *peer_ciphers,
                                    SSL_CIPHER **cipher, void *arg)
{
    dSP;
    int count = -1, res, i;
    AV *ciphers = newAV();
    SV *pref_cipher = sv_newmortal();
    SV * cb_func, *cb_data;

    PR1("STARTED: ssleay_session_secret_cb_invoke\n");
    cb_func = cb_data_advanced_get(arg, "ssleay_session_secret_cb!!func");
    cb_data = cb_data_advanced_get(arg, "ssleay_session_secret_cb!!data");

    if(!SvOK(cb_func))
        croak ("Net::SSLeay: ssleay_ctx_passwd_cb_invoke called, but not set to point to any perl function.\n");

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);

    XPUSHs( sv_2mortal( newSVpv(secret, *secret_len)) );
    for (i=0; i<sk_SSL_CIPHER_num(peer_ciphers); i++) {
        SSL_CIPHER *c = sk_SSL_CIPHER_value(peer_ciphers,i);
        av_store(ciphers, i, sv_2mortal(newSVpv(SSL_CIPHER_get_name(c), 0)));
    }
    XPUSHs(sv_2mortal(newRV_inc((SV*)ciphers)));
    XPUSHs(sv_2mortal(newRV_inc(pref_cipher)));
    XPUSHs(sv_2mortal(newSVsv(cb_data)));

    PUTBACK;

    count = call_sv( cb_func, G_SCALAR );

    SPAGAIN;

    if (count != 1)
        croak ("Net::SSLeay: ssleay_session_secret_cb_invoke perl function did not return a scalar.\n");

    res = POPi;
    if (res) {
        /* See if there is a preferred cipher selected, if so it is an index into the stack */
        if (SvIOK(pref_cipher))
            *cipher = sk_SSL_CIPHER_value(peer_ciphers, SvIV(pref_cipher));
    }

    PUTBACK;
    FREETMPS;
    LEAVE;

    return res;
}

#endif

#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_NEXTPROTONEG)

int next_proto_helper_AV2protodata(AV * list, unsigned char *out)
{
    int i, last_index, ptr = 0;
    last_index = av_len(list);
    if (last_index<0) return 0;
    for(i=0; i<=last_index; i++) {
        char *p = SvPV_nolen(*av_fetch(list, i, 0));
        int len = strlen(p);
        if (len<0 || len>255) return 0;
        if (out) {
            /* if out == NULL we only calculate the length of output */
            out[ptr] = (unsigned char)len;
            strncpy(out+ptr+1, p, len);
        }
        ptr += strlen(p) + 1;
    }
    return ptr;
}

int next_proto_helper_protodata2AV(AV * list, const unsigned char *in, unsigned int inlen)
{
    unsigned int i = 0;
    unsigned char il;
    if (!list || inlen<2) return 0;   
    while (i<inlen) {
        il = in[i++];
        if (i+il > inlen) return 0;
        av_push(list, newSVpv(in+i, il));
        i += il;
    }
    return 1;
}

int next_proto_select_cb_invoke(SSL *ssl, unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen, void *arg)
{
    SV *cb_func, *cb_data;
    unsigned char *next_proto_data;
    unsigned char next_proto_len;
    int next_proto_status;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    STRLEN n_a;

    PR1("STARTED: next_proto_select_cb_invoke\n");
    cb_func = cb_data_advanced_get(ctx, "next_proto_select_cb!!func");
    cb_data = cb_data_advanced_get(ctx, "next_proto_select_cb!!data");
    /* clear last_status value = store undef */
    cb_data_advanced_put(ssl, "next_proto_select_cb!!last_status", NULL);
    cb_data_advanced_put(ssl, "next_proto_select_cb!!last_negotiated", NULL);

    if (SvROK(cb_func) && (SvTYPE(SvRV(cb_func)) == SVt_PVCV)) {
        int count = -1;
        AV *list = newAV();
        SV *tmpsv;
        dSP;
        
        if (!next_proto_helper_protodata2AV(list, in, inlen)) return SSL_TLSEXT_ERR_ALERT_FATAL;

        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSViv(PTR2IV(ssl))));
        XPUSHs(sv_2mortal(newRV_inc((SV*)list)));
        XPUSHs(sv_2mortal(newSVsv(cb_data)));
        PUTBACK;
        count = call_sv( cb_func, G_ARRAY );
        SPAGAIN;
        if (count != 2)
            croak ("Net::SSLeay: next_proto_select_cb_invoke perl function did not return 2 values.\n");
        next_proto_data = POPpx;
        next_proto_status = POPi;
        PUTBACK;
        FREETMPS;
        LEAVE;

        if (strlen(next_proto_data)>255) return SSL_TLSEXT_ERR_ALERT_FATAL;
        next_proto_len = (unsigned char)strlen(next_proto_data);
        /* store last_status + last_negotiated into global hash */
        cb_data_advanced_put(ssl, "next_proto_select_cb!!last_status", newSViv(next_proto_status));
        tmpsv = newSVpv(next_proto_data, next_proto_len);
        cb_data_advanced_put(ssl, "next_proto_select_cb!!last_negotiated", tmpsv);
        *out = (unsigned char *)SvPVX(tmpsv);
        *outlen = next_proto_len;
        return SSL_TLSEXT_ERR_OK;
    }
    else if (SvROK(cb_data) && (SvTYPE(SvRV(cb_data)) == SVt_PVAV)) {
        next_proto_len = next_proto_helper_AV2protodata((AV*)SvRV(cb_data), NULL);
        Newx(next_proto_data, next_proto_len, unsigned char);
        if (!next_proto_data) return SSL_TLSEXT_ERR_ALERT_FATAL;
        next_proto_len = next_proto_helper_AV2protodata((AV*)SvRV(cb_data), next_proto_data);

        next_proto_status = SSL_select_next_proto(out, outlen, in, inlen, next_proto_data, next_proto_len);

        /* store last_status + last_negotiated into global hash */
        cb_data_advanced_put(ssl, "next_proto_select_cb!!last_status", newSViv(next_proto_status));
        cb_data_advanced_put(ssl, "next_proto_select_cb!!last_negotiated", newSVpv(*out, *outlen));
        Safefree(next_proto_data);
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int next_protos_advertised_cb_invoke(SSL *ssl, const unsigned char **out, unsigned int *outlen, void *arg_unused)
{
    SV *cb_func, *cb_data;
    unsigned char *protodata = NULL;
    unsigned short protodata_len = 0;
    SV *tmpsv;
    AV *tmpav;
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);

    PR1("STARTED: next_protos_advertised_cb_invoke");
    cb_func = cb_data_advanced_get(ctx, "next_protos_advertised_cb!!func");
    cb_data = cb_data_advanced_get(ctx, "next_protos_advertised_cb!!data");

    if (SvROK(cb_func) && (SvTYPE(SvRV(cb_func)) == SVt_PVCV)) {
        int count = -1;
        dSP;
        ENTER;
        SAVETMPS;
        PUSHMARK(SP);
        XPUSHs(sv_2mortal(newSViv(PTR2IV(ssl))));
        XPUSHs(sv_2mortal(newSVsv(cb_data)));
        PUTBACK;
        count = call_sv( cb_func, G_SCALAR );
        SPAGAIN;
        if (count != 1)
            croak ("Net::SSLeay: next_protos_advertised_cb_invoke perl function did not return scalar value.\n");
        tmpsv = POPs;
        if (SvOK(tmpsv) && SvROK(tmpsv) && (SvTYPE(SvRV(tmpsv)) == SVt_PVAV)) {
            tmpav = (AV*)SvRV(tmpsv);
            protodata_len = next_proto_helper_AV2protodata(tmpav, NULL);
            Newx(protodata, protodata_len, unsigned char);
            if (protodata) next_proto_helper_AV2protodata(tmpav, protodata);
        }
        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    else if (SvROK(cb_data) && (SvTYPE(SvRV(cb_data)) == SVt_PVAV)) {
        tmpav = (AV*)SvRV(cb_data);
        protodata_len = next_proto_helper_AV2protodata(tmpav, NULL);
        Newx(protodata, protodata_len, unsigned char);
        if (protodata) next_proto_helper_AV2protodata(tmpav, protodata);
    }    
    if (protodata) {
        tmpsv = newSVpv(protodata, protodata_len);
        Safefree(protodata);
        cb_data_advanced_put(ssl, "next_protos_advertised_cb!!last_advertised", tmpsv);
        *out = (unsigned char *)SvPVX(tmpsv);
        *outlen = protodata_len;
        return SSL_TLSEXT_ERR_OK;
    }
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#endif

int pem_password_cb_invoke(char *buf, int bufsize, int rwflag, void *data) {
    dSP;
    char *str;
    int count = -1, str_len = 0;
    simple_cb_data_t* cb = (simple_cb_data_t*)data;
    STRLEN n_a;

    PR1("STARTED: pem_password_cb_invoke\n");
    if (cb->func && SvOK(cb->func)) {
        ENTER;
        SAVETMPS;

        PUSHMARK(sp);

        XPUSHs(sv_2mortal( newSViv(bufsize-1) ));
        XPUSHs(sv_2mortal( newSViv(rwflag) ));
        if (cb->data) XPUSHs( cb->data );

        PUTBACK;

        count = call_sv( cb->func, G_SCALAR );

        SPAGAIN;

        buf[0] = 0; /* start with an empty password */
        if (count != 1) {
            croak("Net::SSLeay: pem_password_cb_invoke perl function did not return a scalar.\n");
        }
        else {
            str = POPpx;
            str_len = strlen(str);
            if (str_len+1 < bufsize) {
                strcpy(buf, str);
            }
            else {
                str_len = 0;
                warn("Net::SSLeay: pem_password_cb_invoke password too long\n");
            }
        }

        PUTBACK;
        FREETMPS;
        LEAVE;
    }
    return str_len;
}

void ssleay_RSA_generate_key_cb_invoke(int i, int n, void* data)
{
    dSP;
    int count = -1;
    simple_cb_data_t* cb = (simple_cb_data_t*)data;

    /* PR1("STARTED: ssleay_RSA_generate_key_cb_invoke\n"); / * too noisy */
    if (cb->func && SvOK(cb->func)) {
        ENTER;
        SAVETMPS;

        PUSHMARK(sp);

        XPUSHs(sv_2mortal( newSViv(i) ));
        XPUSHs(sv_2mortal( newSViv(n) ));
        if (cb->data) XPUSHs( cb->data );

        PUTBACK;

        count = call_sv( cb->func, G_VOID|G_DISCARD );

        if (count != 0)
            croak ("Net::SSLeay: ssleay_RSA_generate_key_cb_invoke "
                   "perl function did return something in void context.\n");

        PUTBACK;
        FREETMPS;
        LEAVE;
    }
}

/* ============= end of callback stuff ============== */

MODULE = Net::SSLeay		PACKAGE = Net::SSLeay          PREFIX = SSL_

PROTOTYPES: ENABLE

BOOT:
    {
    MY_CXT_INIT;
    LIB_initialized = 0;
#ifdef USE_ITHREADS
    MUTEX_INIT(&LIB_init_mutex);
#ifdef OPENSSL_THREADS
    /* If we running under ModPerl, we dont need our own thread locking because
     * perl threads are not supported under mod-perl, and we can fall back to the thread
     * locking built in to mod-ssl      
     */
     if (!hv_fetch(get_hv("ENV", 1), "MOD_PERL", 8, 0))
	openssl_threads_init();
#endif
#endif
    /* initialize global shared callback data hash */
    MY_CXT.global_cb_data = newHV();
    MY_CXT.tid = get_my_thread_id();
    PR3("BOOT: tid=%d my_perl=0x%p\n", MY_CXT.tid, my_perl);
    }

void
CLONE(...)
CODE:
    MY_CXT_CLONE;
    /* reset all callback related data as we want to prevent 
     * cross-thread callbacks
     * TODO: later somebody can make the global hash MY_CXT.global_cb_data
     * somehow shared between threads
     */
    MY_CXT.global_cb_data = newHV();
    MY_CXT.tid = get_my_thread_id();
    PR3("CLONE: tid=%d my_perl=0x%p\n", MY_CXT.tid, my_perl);

double
constant(name)
        char * name
    CODE:
        errno = 0;
        RETVAL = constant(name, strlen(name));
    OUTPUT:
        RETVAL

int
hello()
        CODE:
        PR1("\tSSLeay Hello World!\n");
        RETVAL = 1;
        OUTPUT:
        RETVAL

#define REM0 "============= version related functions =============="

unsigned long
SSLeay()

const char *
SSLeay_version(type=0)
        int type

#define REM1 "============= SSL CONTEXT functions =============="

SSL_CTX *
SSL_CTX_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv23_method());
     OUTPUT:
     RETVAL

#ifndef OPENSSL_NO_SSL2
#if OPENSSL_VERSION_NUMBER < 0x10000000L

SSL_CTX *
SSL_CTX_v2_new()
     CODE:
     RETVAL = SSL_CTX_new (SSLv2_method());
     OUTPUT:
     RETVAL

#endif
#endif

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
     SSL_METHOD * meth
     CODE:
     RETVAL = SSL_CTX_new (meth);
     OUTPUT:
     RETVAL

void
SSL_CTX_free(ctx)
        SSL_CTX * ctx
     CODE:
        cb_data_advanced_drop(ctx); /* clean callback related data from global hash */
        SSL_CTX_free(ctx);

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
SSL_CTX_set_verify(ctx,mode,callback=&PL_sv_undef)
        SSL_CTX * ctx
        int mode
        SV * callback
    CODE:

    /* Former versions of SSLeay checked if the callback was a true boolean value
     * and didn't call it if it was false. Therefor some people set the callback
     * to '0' if they don't want to use it (IO::Socket::SSL for example). Therefor
     * we don't execute the callback if it's value isn't something true to retain
     * backwards compatibility.
     */

    if (callback==NULL || !SvOK(callback) || !SvTRUE(callback)) {
        SSL_CTX_set_verify(ctx, mode, NULL);
        cb_data_advanced_put(ctx, "ssleay_verify_callback!!func", NULL);
    } else {
        cb_data_advanced_put(ctx, "ssleay_verify_callback!!func", newSVsv(callback));
        SSL_CTX_set_verify(ctx, mode, &ssleay_verify_callback_invoke);
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
        SSL * s
     CODE:
        cb_data_advanced_drop(s); /* clean callback related data from global hash */
        SSL_free(s);

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
     perl_filehandle_t     fd
     CODE:
     RETVAL = SSL_set_fd(s,_get_osfhandle(fd));
     OUTPUT:
     RETVAL

int
SSL_set_rfd(s,fd)
     SSL *   s
     perl_filehandle_t     fd
     CODE:
     RETVAL = SSL_set_rfd(s,_get_osfhandle(fd));
     OUTPUT:
     RETVAL

int
SSL_set_wfd(s,fd)
     SSL *   s
     perl_filehandle_t     fd
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
	New(0, buf, max, char);
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = SSL_read(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	Safefree(buf);

void
SSL_peek(s,max=32768)
	SSL *   s
	int     max
	PREINIT:
	char *buf;
	int got;
	CODE:
	New(0, buf, max, char);
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = SSL_peek(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	Safefree(buf);

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
     STRLEN ulen;
     IV len;
     INPUT:
     char *  buf = SvPV( ST(3), ulen);
     CODE:
      /*
     if (SvROK( ST(3) )) {
       SV* t = SvRV( ST(3) );
       buf = SvPV( t, len);
     } else
       buf = SvPV( ST(3), len);
       */
     PR4("write_partial from=%d count=%d len=%ul\n",from,count,ulen);
     /*PR2("buf='%s'\n",&buf[from]); / * too noisy */
     len = (IV)ulen;
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

void
SSL_get_shared_ciphers(s,ignored_param1=0,ignored_param2=0)
        SSL *s
        int ignored_param1
        int ignored_param2
    PREINIT:
        char buf[8192];
    CODE:
        ST(0) = sv_newmortal();   /* undef to start with */
        if(SSL_get_shared_ciphers(s, buf, sizeof(buf)))
            sv_setpvn(ST(0), buf, strlen(buf));

X509 *
SSL_get_peer_certificate(s)
     SSL *              s

void
SSL_set_verify(s,mode,callback)
        SSL * s
        int mode
        SV * callback
    CODE:
        if (callback==NULL || !SvOK(callback)) {
            SSL_set_verify(s, mode, NULL);
            cb_data_advanced_put(s, "ssleay_verify_callback!!func", NULL);
        }
        else {
            cb_data_advanced_put(s, "ssleay_verify_callback!!func", newSVsv(callback));
            SSL_set_verify(s, mode, &ssleay_verify_callback_invoke);
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

#if OPENSSL_VERSION_NUMBER < 0x0090707fL
#define REM3 "NOTE: before 0.9.7g"

SSL_SESSION *
d2i_SSL_SESSION(a,pp,length)
     SSL_SESSION *      &a
     unsigned char *    &pp
     long               length

#else

SSL_SESSION *
d2i_SSL_SESSION(a,pp,length)
     SSL_SESSION *      &a
     const unsigned char *    &pp
     long               length

#endif
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

long
SSL_set_options(ssl,op)
     SSL *          ssl
     long	    op

long
SSL_CTX_get_options(ctx)
     SSL_CTX *      ctx

long
SSL_CTX_set_options(ctx,op)
     SSL_CTX *      ctx
     long	    op

#if OPENSSL_VERSION_NUMBER >= 0x10000000L

struct lhash_st_SSL_SESSION *
SSL_CTX_sessions(ctx)
     SSL_CTX *          ctx

#else

LHASH *
SSL_CTX_sessions(ctx)
     SSL_CTX *          ctx
     CODE:
    /* NOTE: This should be deprecated. Corresponding macro was removed from ssl.h as of 0.9.2 */
     if (ctx == NULL) croak("NULL SSL context passed as argument.");
     RETVAL = ctx -> sessions;
     OUTPUT:
     RETVAL

#endif

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

long
SSL_CTX_sess_set_cache_size(ctx,size)
     SSL_CTX *          ctx
     int                size

int
SSL_want(s)
     SSL *              s

int
SSL_state(s)
     SSL *              s

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)

long
SSL_set_tlsext_host_name(SSL *ssl, const char *name)

#endif

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
	CODE:
#ifdef USE_ITHREADS
		MUTEX_LOCK(&LIB_init_mutex);
#endif
		RETVAL = 0;
		if (!LIB_initialized) {
			RETVAL = SSL_library_init();
			LIB_initialized = 1;
		}
#ifdef USE_ITHREADS
		MUTEX_UNLOCK(&LIB_init_mutex);
#endif
	OUTPUT:
	RETVAL

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
#define REM5 "NOTE: requires 0.9.7+"

void
ENGINE_load_builtin_engines()

void
ENGINE_register_all_complete()

ENGINE*
ENGINE_by_id(id)
	char * id

int
ENGINE_set_default(e, flags)
        ENGINE * e
        int flags

#endif

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

int
X509_set_issuer_name(X509 *x, X509_NAME *name)

int
X509_set_subject_name(X509 *x, X509_NAME *name)

int
X509_set_version(X509 *x, long version)

int
X509_set_pubkey(X509 *x, EVP_PKEY *pkey)

long
X509_get_version(X509 *x)

EVP_PKEY *
X509_get_pubkey(X509 *x)

ASN1_INTEGER *
X509_get_serialNumber(X509 *x)

int
X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial)

int
X509_certificate_type(X509 *x, EVP_PKEY *pubkey=NULL);

int
X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md)

int
X509_verify(X509 *x, EVP_PKEY *r)

void
X509_NAME_oneline(name)
	X509_NAME *    name
	PREINIT:
	char * buf;
	CODE:
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((buf = X509_NAME_oneline(name, NULL, 0))) {
		sv_setpvn( ST(0), buf, strlen(buf));
		OPENSSL_free(buf); /* mem was allocated by openssl */
	}

void
X509_NAME_print_ex(name,flags=XN_FLAG_RFC2253,utf8_decode=0)
        X509_NAME * name
        unsigned long flags
        int utf8_decode
    PREINIT:
        char * buf;
        BIO * bp;
        int n, i, ident=0;
    CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp) {
            if (X509_NAME_print_ex(bp, name, ident, flags)) {
                n = BIO_ctrl_pending(bp);
                New(0, buf, n, char);
                if (buf) {
                    i = BIO_read(bp,buf,n);
                    if (i>=0 && i<=n) {
                        sv_setpvn(ST(0), buf, i);
                        if (utf8_decode) sv_utf8_decode(ST(0));
                    }
                    Safefree(buf);
                }
            }
            BIO_free(bp);
        }

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

       if (length>=0) {
               New(0, buf, length+1, char);
               if (X509_NAME_get_text_by_NID(name, nid, buf, length + 1)>=0)
                       sv_setpvn( ST(0), buf, length);
               Safefree(buf);
       }

#if OPENSSL_VERSION_NUMBER >= 0x0090500fL
#define REM17 "requires 0.9.5+"

int
X509_NAME_add_entry_by_NID(name,nid,type,bytes,loc=-1,set=0)
        X509_NAME *name
        int nid
        int type
        int loc
        int set
    PREINIT:
        STRLEN len;
    INPUT:
        unsigned char *bytes = (unsigned char *)SvPV(ST(3), len);
    CODE:
        RETVAL = X509_NAME_add_entry_by_NID(name,nid,type,bytes,len,loc,set);
    OUTPUT:
        RETVAL

int
X509_NAME_add_entry_by_OBJ(name,obj,type,bytes,loc=-1,set=0)
        X509_NAME *name
        ASN1_OBJECT *obj
        int type
        int loc
        int set
    PREINIT:
        STRLEN len;
    INPUT:
        unsigned char *bytes = (unsigned char *)SvPV(ST(3), len);
    CODE:
        RETVAL = X509_NAME_add_entry_by_OBJ(name,obj,type,bytes,len,loc,set);
    OUTPUT:
        RETVAL

int
X509_NAME_add_entry_by_txt(name,field,type,bytes,loc=-1,set=0)
        X509_NAME *name
        char *field
        int type
        int loc
        int set
    PREINIT:
        STRLEN len;
    INPUT:
        unsigned char *bytes = (unsigned char *)SvPV(ST(3), len);
    CODE:
        RETVAL = X509_NAME_add_entry_by_txt(name,field,type,bytes,len,loc,set);
    OUTPUT:
        RETVAL

#endif

int
X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b)

int
X509_NAME_entry_count(X509_NAME *name)

X509_NAME_ENTRY *
X509_NAME_get_entry(X509_NAME *name, int loc)

ASN1_STRING *
X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *ne)

ASN1_OBJECT *
X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *ne)

void
X509_CRL_free(X509_CRL *x)

X509_CRL *
X509_CRL_new()

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
#define REM19 "requires 0.9.7+"

int
X509_CRL_set_version(X509_CRL *x, long version)

int
X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name)

int
X509_CRL_set_lastUpdate(X509_CRL *x, ASN1_TIME *tm)

int
X509_CRL_set_nextUpdate(X509_CRL *x, ASN1_TIME *tm)

int
X509_CRL_sort(X509_CRL *x)

#endif

long
X509_CRL_get_version(X509_CRL *x)

X509_NAME *
X509_CRL_get_issuer(X509_CRL *x)

ASN1_TIME *
X509_CRL_get_lastUpdate(X509_CRL *x)

ASN1_TIME *
X509_CRL_get_nextUpdate(X509_CRL *x)

int
X509_CRL_verify(X509_CRL *a, EVP_PKEY *r)

int
X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md)

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
#define REM20 "requires 0.9.7+"

int
P_X509_CRL_set_serial(crl,crl_number)
        X509_CRL *crl
        ASN1_INTEGER * crl_number;
    CODE:
        RETVAL = 0;
        if (crl && crl_number)
            if (X509_CRL_add1_ext_i2d(crl, NID_crl_number, crl_number, 0, 0)) RETVAL = 1;
    OUTPUT:
        RETVAL

ASN1_INTEGER *
P_X509_CRL_get_serial(crl)
        X509_CRL *crl
    INIT:
        int i;
    CODE:
        RETVAL = (ASN1_INTEGER *)X509_CRL_get_ext_d2i(crl, NID_crl_number, &i, NULL);
        if (!RETVAL || i==-1) XSRETURN_UNDEF;
    OUTPUT:
        RETVAL

void
P_X509_CRL_add_revoked_serial_hex(crl,serial_hex,rev_time,reason_code=0,comp_time=NULL)
        X509_CRL *crl
        char * serial_hex
        ASN1_TIME *rev_time
        long reason_code
        ASN1_TIME *comp_time
    PREINIT:
        BIGNUM *bn = NULL;
        ASN1_INTEGER *sn;
        X509_REVOKED *rev;
        ASN1_ENUMERATED *rsn = NULL;
        int rv;
    PPCODE:
        rv=0;
        rev = X509_REVOKED_new();
        if (rev) {
            if (BN_hex2bn(&bn, serial_hex)) {
                sn = BN_to_ASN1_INTEGER(bn, NULL);
                if (sn) {
                    X509_REVOKED_set_serialNumber(rev, sn);
                    ASN1_INTEGER_free(sn);
                    rv = 1;
                }
                BN_free(bn);
            }
        }
        if (!rv) XSRETURN_IV(0);

        if (!rev_time) XSRETURN_IV(0);
        if (!X509_REVOKED_set_revocationDate(rev, rev_time)) XSRETURN_IV(0);

        if(reason_code) {
            rv = 0;
            rsn = ASN1_ENUMERATED_new();
            if (rsn) {
                if (ASN1_ENUMERATED_set(rsn, reason_code))
                    if (X509_REVOKED_add1_ext_i2d(rev, NID_crl_reason, rsn, 0, 0))
                        rv=1;
                ASN1_ENUMERATED_free(rsn);
            }
            if (!rv) XSRETURN_IV(0);
        }

        if(comp_time) {
            X509_REVOKED_add1_ext_i2d(rev, NID_invalidity_date, comp_time, 0, 0);
        }

        if(!X509_CRL_add0_revoked(crl, rev)) XSRETURN_IV(0);
        XSRETURN_IV(1);

#endif

X509_REQ *
X509_REQ_new()

void
X509_REQ_free(X509_REQ *x)

X509_NAME *
X509_REQ_get_subject_name(X509_REQ *x)

int
X509_REQ_set_subject_name(X509_REQ *x, X509_NAME *name)

int
X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey)

EVP_PKEY *
X509_REQ_get_pubkey(X509_REQ *x)

int
X509_REQ_sign(X509_REQ *x, EVP_PKEY *pk, const EVP_MD *md)

int
X509_REQ_verify(X509_REQ *x, EVP_PKEY *r)

int
X509_REQ_set_version(X509_REQ *x, long version)

long
X509_REQ_get_version(X509_REQ *x)

int
X509_REQ_get_attr_count(const X509_REQ *req);

int
X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos=-1)

int
X509_REQ_get_attr_by_OBJ(const X509_REQ *req, ASN1_OBJECT *obj, int lastpos=-1)

int
X509_REQ_add1_attr_by_NID(req,nid,type,bytes)
        X509_REQ *req
        int nid
        int type
    PREINIT:
        STRLEN len;
    INPUT:
        unsigned char *bytes = (unsigned char *)SvPV(ST(3), len);
    CODE:
        RETVAL = X509_REQ_add1_attr_by_NID(req,nid,type,bytes,len);
    OUTPUT:
        RETVAL

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
#define REM21 "requires 0.9.7+"

void
P_X509_REQ_get_attr(req,n)
        X509_REQ *req
        int n
    INIT:
        X509_ATTRIBUTE * att;
        int count, i;
        ASN1_STRING * s;
    PPCODE:
        att = X509_REQ_get_attr(req,n);
        if (att->single) {
            s = (att->value.single->value.asn1_string);
            XPUSHs(sv_2mortal(newSViv(PTR2IV(s))));
        }
        else {
            count = sk_ASN1_TYPE_num(att->value.set);
            for (i=0; i<count; i++) {
                s = (sk_ASN1_TYPE_value(att->value.set, i)->value.asn1_string);
                XPUSHs(sv_2mortal(newSViv(PTR2IV(s))));
            }
        }

#endif

int
P_X509_REQ_add_extensions(x,...)
        X509_REQ *x
    PREINIT:
        int i=1;
        int nid;
        char *data;
        X509_EXTENSION *ex;
        STACK_OF(X509_EXTENSION) *stack;
    CODE:
        if (items>1) {
            RETVAL = 1;
            stack = sk_X509_EXTENSION_new_null();
            while(i+1<items) {
                nid = SvIV(ST(i));
                data = SvPV_nolen(ST(i+1));
                i+=2;
                ex = X509V3_EXT_conf_nid(NULL, NULL, nid, data);
                if (ex)
                    sk_X509_EXTENSION_push(stack, ex);
                else
                    RETVAL = 0;
            }
            X509_REQ_add_extensions(x, stack);
            sk_X509_EXTENSION_pop_free(stack, X509_EXTENSION_free);
        }
        else
            RETVAL = 0;
    OUTPUT:
        RETVAL

int
P_X509_add_extensions(x,ca_cert,...)
        X509 *x
        X509 *ca_cert
    PREINIT:
        int i=2;
        int nid;
        char *data;
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
    CODE:
        if (items>1) {
            RETVAL = 1;
            while(i+1<items) {
                nid = SvIV(ST(i));
                data = SvPV_nolen(ST(i+1));
                i+=2;
                X509V3_set_ctx(&ctx, ca_cert, x, NULL, NULL, 0);
                ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, data);
                if (ex) {
                    X509_add_ext(x,ex,-1);
                    X509_EXTENSION_free(ex);
                }
                else {
                    warn("failure during X509V3_EXT_conf_nid() for nid=%d\n", nid);
                    ERR_print_errors_fp(stderr);
                    RETVAL = 0;
                }
            }
        }
        else
            RETVAL = 0;
    OUTPUT:
            RETVAL

void
P_X509_copy_extensions(x509_req,x509,override=1)
        X509_REQ *x509_req
        X509 *x509
        int override
    PREINIT:
        STACK_OF(X509_EXTENSION) *exts = NULL;
        X509_EXTENSION *ext, *tmpext;
        ASN1_OBJECT *obj;
        int i, idx, ret = 1;
    PPCODE:
        if (!x509 || !x509_req) XSRETURN_IV(0);
        exts = X509_REQ_get_extensions(x509_req);
        for(i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
            ext = sk_X509_EXTENSION_value(exts, i);
            obj = X509_EXTENSION_get_object(ext);
            idx = X509_get_ext_by_OBJ(x509, obj, -1);
            /* Does extension exist? */
            if (idx != -1) {
                if (override) continue; /* don't override existing extension */
                /* Delete all extensions of same type */
                do {
                    tmpext = X509_get_ext(x509, idx);
                    X509_delete_ext(x509, idx);
                    X509_EXTENSION_free(tmpext);
                    idx = X509_get_ext_by_OBJ(x509, obj, -1);
                } while (idx != -1);
            }
            if (!X509_add_ext(x509, ext, -1)) ret = 0;
        }
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        XSRETURN_IV(ret);

X509 *
X509_STORE_CTX_get_current_cert(x509_store_ctx)
     X509_STORE_CTX * 	x509_store_ctx

void *
X509_STORE_CTX_get_ex_data(x509_store_ctx,idx)
     X509_STORE_CTX * x509_store_ctx
     int idx

void
X509_get_fingerprint(cert,type)
		X509 * 	cert
		char *	type
	PREINIT:
		const EVP_MD *digest_tp = NULL;
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int dsz, k = 0;
		char text[EVP_MAX_MD_SIZE * 3 + 1];
	CODE:
		if (!k && !strcmp(type,"md5")) {
		 	k = 1; digest_tp = EVP_md5();
		}
		if (!k && !strcmp(type,"sha1")) {
			k = 1; digest_tp = EVP_sha1();
		}
#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_SHA256
		if (!k && !strcmp(type,"sha256")) {
			k = 1; digest_tp = EVP_sha256();
		}
#endif
#endif
		if (!k && !strcmp(type,"ripemd160")) {
			k = 1; digest_tp = EVP_ripemd160();
		}
		if (!k)	/* Default digest */
			digest_tp = EVP_sha1();
		if ( digest_tp == NULL ) {
			/* Out of memory */
			XSRETURN_UNDEF;
		}
		if (!X509_digest(cert, digest_tp, digest, &dsz)) {
			/* Out of memory */
			XSRETURN_UNDEF;
		}
		text[0] = '\0';
		for(k=0; k<dsz; k++) {
			sprintf(&text[strlen(text)], "%02X:", digest[k]);
		}
		text[strlen(text)-1] = '\0';
		ST(0) = sv_newmortal();   /* Undefined to start with */
		sv_setpvn( ST(0), text, strlen(text));

void
X509_get_subjectAltNames(cert)
	X509 *      cert
	PPCODE:
	int                    i, j, count = 0;
	X509_EXTENSION         *subjAltNameExt = NULL;
	STACK_OF(GENERAL_NAME) *subjAltNameDNs = NULL;
	GENERAL_NAME           *subjAltNameDN  = NULL;
	int                    num_gnames;
	if (  (i = X509_get_ext_by_NID(cert, NID_subject_alt_name, -1)) >= 0
		&& (subjAltNameExt = X509_get_ext(cert, i))
		&& (subjAltNameDNs = X509V3_EXT_d2i(subjAltNameExt)))
	{
		num_gnames = sk_GENERAL_NAME_num(subjAltNameDNs);

		for (j = 0; j < num_gnames; j++)
                {
		     subjAltNameDN = sk_GENERAL_NAME_value(subjAltNameDNs, j);

                     switch (subjAltNameDN->type)
                     {
                     case GEN_OTHERNAME:
                         EXTEND(SP, 2);
                         count++;
                         PUSHs(sv_2mortal(newSViv(subjAltNameDN->type)));
                         PUSHs(sv_2mortal(newSVpv((const char*)ASN1_STRING_data(subjAltNameDN->d.otherName->value->value.utf8string), ASN1_STRING_length(subjAltNameDN->d.otherName->value->value.utf8string))));
                         break;

                     case GEN_EMAIL:
                     case GEN_DNS:
                     case GEN_URI:
                         EXTEND(SP, 2);
                         count++;
                         PUSHs(sv_2mortal(newSViv(subjAltNameDN->type)));
                         PUSHs(sv_2mortal(newSVpv((const char*)ASN1_STRING_data(subjAltNameDN->d.ia5), ASN1_STRING_length(subjAltNameDN->d.ia5))));
                         break;

                     case GEN_DIRNAME:
                         {
                         char * buf = X509_NAME_oneline(subjAltNameDN->d.dirn, NULL, 0);
                         EXTEND(SP, 2);
                         count++;
                         PUSHs(sv_2mortal(newSViv(subjAltNameDN->type)));
                         PUSHs(sv_2mortal(newSVpv((buf), strlen((buf)))));
                         break;
                         }

                     case GEN_IPADD:
                         EXTEND(SP, 2);
                         count++;
                         PUSHs(sv_2mortal(newSViv(subjAltNameDN->type)));
                         PUSHs(sv_2mortal(newSVpv((const char*)subjAltNameDN->d.ip->data, subjAltNameDN->d.ip->length)));
                         break;

                     }
		}
	}
	XSRETURN(count * 2);

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL

void
P_X509_get_crl_distribution_points(cert)
        X509 * cert
    INIT:
        GENERAL_NAMES *gnames;
        GENERAL_NAME *gn;
        STACK_OF(DIST_POINT) *points;
        DIST_POINT *p;
        int i, j;
    PPCODE:
        points = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
        if (points)
        for (i = 0; i < sk_DIST_POINT_num(points); i++) {
            p = sk_DIST_POINT_value(points, i);
            if (!p->distpoint)
                continue;
            if (p->distpoint->type == 0) {
                /* full name */
                gnames = p->distpoint->name.fullname;
                for (j = 0; j < sk_GENERAL_NAME_num(gnames); j++) {
                    gn = sk_GENERAL_NAME_value(gnames, j);
                    XPUSHs(sv_2mortal(newSVpv((char*)ASN1_STRING_data(gn->d.ia5),ASN1_STRING_length(gn->d.ia5))));
                }
            }
            else {
                /* relative name - not supported */
                /* XXX-TODO: the code below is just an idea; do not enable it without proper test case
                BIO *bp;
                char *buf;
                int n;
                X509_NAME ntmp;
                ntmp.entries = p->distpoint->name.relativename;
                bp = BIO_new(BIO_s_mem());
                if (bp) {
                    X509_NAME_print_ex(bp, &ntmp, 0, XN_FLAG_RFC2253);
                    n = BIO_ctrl_pending(bp);
                    New(0, buf, n, char);
                    if (buf) {
                        j = BIO_read(bp,buf,n);
                        if (j>=0 && j<=n) XPUSHs(sv_2mortal(newSVpvn(buf,j)));
                        Safefree(buf);
                    }
                    BIO_free(bp);
                }
                */
            }
        }

void
P_X509_get_ext_key_usage(cert,format=0)
        X509 * cert
        int format
    PREINIT:
        EXTENDED_KEY_USAGE *extusage;
        int i, nid;
        char buffer[100]; /* openssl doc: a buffer length of 80 should be more than enough to handle any OID encountered in practice */
        ASN1_OBJECT *o;
    PPCODE:
        extusage = X509_get_ext_d2i(cert, NID_ext_key_usage, NULL, NULL);
        for(i = 0; i < sk_ASN1_OBJECT_num(extusage); i++) {
           o = sk_ASN1_OBJECT_value(extusage,i);
           nid = OBJ_obj2nid(o);
           OBJ_obj2txt(buffer, sizeof(buffer)-1, o, 1);
           if(format==0)
               XPUSHs(sv_2mortal(newSVpv(buffer,0)));          /* format 0: oid */
           else if(format==1 && nid>0)
               XPUSHs(sv_2mortal(newSViv(nid)));               /* format 1: nid */
           else if(format==2 && nid>0)
               XPUSHs(sv_2mortal(newSVpv(OBJ_nid2sn(nid),0))); /* format 2: shortname */
           else if(format==3 && nid>0)
               XPUSHs(sv_2mortal(newSVpv(OBJ_nid2ln(nid),0))); /* format 3: longname */
        }

#endif

void
P_X509_get_key_usage(cert)
        X509 * cert
    INIT:
        ASN1_BIT_STRING * u;
    PPCODE:
        u = X509_get_ext_d2i(cert, NID_key_usage, NULL, NULL);
        if (u) {
            if (ASN1_BIT_STRING_get_bit(u,0)) XPUSHs(sv_2mortal(newSVpv("digitalSignature",0)));
            if (ASN1_BIT_STRING_get_bit(u,1)) XPUSHs(sv_2mortal(newSVpv("nonRepudiation",0)));
            if (ASN1_BIT_STRING_get_bit(u,2)) XPUSHs(sv_2mortal(newSVpv("keyEncipherment",0)));
            if (ASN1_BIT_STRING_get_bit(u,3)) XPUSHs(sv_2mortal(newSVpv("dataEncipherment",0)));
            if (ASN1_BIT_STRING_get_bit(u,4)) XPUSHs(sv_2mortal(newSVpv("keyAgreement",0)));
            if (ASN1_BIT_STRING_get_bit(u,5)) XPUSHs(sv_2mortal(newSVpv("keyCertSign",0)));
            if (ASN1_BIT_STRING_get_bit(u,6)) XPUSHs(sv_2mortal(newSVpv("cRLSign",0)));
            if (ASN1_BIT_STRING_get_bit(u,7)) XPUSHs(sv_2mortal(newSVpv("encipherOnly",0)));
            if (ASN1_BIT_STRING_get_bit(u,8)) XPUSHs(sv_2mortal(newSVpv("decipherOnly",0)));
        }

void
P_X509_get_netscape_cert_type(cert)
        X509 * cert
    INIT:
        ASN1_BIT_STRING * u;
    PPCODE:
        u = X509_get_ext_d2i(cert, NID_netscape_cert_type, NULL, NULL);
        if (u) {
            if (ASN1_BIT_STRING_get_bit(u,0)) XPUSHs(sv_2mortal(newSVpv("client",0)));
            if (ASN1_BIT_STRING_get_bit(u,1)) XPUSHs(sv_2mortal(newSVpv("server",0)));
            if (ASN1_BIT_STRING_get_bit(u,2)) XPUSHs(sv_2mortal(newSVpv("email",0)));
            if (ASN1_BIT_STRING_get_bit(u,3)) XPUSHs(sv_2mortal(newSVpv("objsign",0)));
            if (ASN1_BIT_STRING_get_bit(u,4)) XPUSHs(sv_2mortal(newSVpv("reserved",0)));
            if (ASN1_BIT_STRING_get_bit(u,5)) XPUSHs(sv_2mortal(newSVpv("sslCA",0)));
            if (ASN1_BIT_STRING_get_bit(u,6)) XPUSHs(sv_2mortal(newSVpv("emailCA",0)));
            if (ASN1_BIT_STRING_get_bit(u,7)) XPUSHs(sv_2mortal(newSVpv("objCA",0)));
        }

int
X509_get_ext_by_NID(x,nid,loc=-1)
	X509* x
	int nid
	int loc

X509_EXTENSION *
X509_get_ext(x,loc)
	X509* x
	int loc

int
X509_EXTENSION_get_critical(X509_EXTENSION *ex)

ASN1_OCTET_STRING *
X509_EXTENSION_get_data(X509_EXTENSION *ne)

ASN1_OBJECT *
X509_EXTENSION_get_object(X509_EXTENSION *ex)

int
X509_get_ext_count(X509 *x)

void
X509V3_EXT_print(ext,flags=0,utf8_decode=0)
        X509_EXTENSION * ext
        unsigned long flags
        int utf8_decode
    PREINIT:
        BIO * bp;
        char * buf;
        int i, n;
        int indent=0;
    CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp) {
            if(X509V3_EXT_print(bp,ext,flags,indent)) {
                n = BIO_ctrl_pending(bp);
                New(0, buf, n, char);
                if (buf) {
                    i = BIO_read(bp,buf,n);
                    if (i>=0 && i<=n) {
                        sv_setpvn(ST(0), buf, i);
                        if (utf8_decode) sv_utf8_decode(ST(0));
                    }
                    Safefree(buf);
                }
            }
            BIO_free(bp);
        }

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

int
X509_STORE_set1_param(ctx, pm)
    X509_STORE *ctx
    X509_VERIFY_PARAM *pm

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

ASN1_INTEGER *
ASN1_INTEGER_new()

void
ASN1_INTEGER_free(ASN1_INTEGER *i)

int
ASN1_INTEGER_set(ASN1_INTEGER *i, long val)

long
ASN1_INTEGER_get(ASN1_INTEGER *a)

void
P_ASN1_INTEGER_set_hex(i,str)
        ASN1_INTEGER * i
        char * str
    INIT:
        BIGNUM *bn;
        int rv = 1;
    PPCODE:
        bn = BN_new();
        if (!BN_hex2bn(&bn, str)) XSRETURN_IV(0);
        if (!BN_to_ASN1_INTEGER(bn, i)) rv = 0;
        BN_free(bn);
        XSRETURN_IV(rv);

void
P_ASN1_INTEGER_set_dec(i,str)
        ASN1_INTEGER * i
        char * str
    INIT:
        BIGNUM *bn;
        int rv = 1;
    PPCODE:
        bn = BN_new();
        if (!BN_dec2bn(&bn, str)) XSRETURN_IV(0);
        if (!BN_to_ASN1_INTEGER(bn, i)) rv = 0;
        BN_free(bn);
        XSRETURN_IV(rv);

void
P_ASN1_INTEGER_get_hex(i)
        ASN1_INTEGER * i
    INIT:
        BIGNUM *bn;
        char *result;
    PPCODE:
        bn = BN_new();
        if (!bn) XSRETURN_UNDEF;
        ASN1_INTEGER_to_BN(i, bn);
        result = BN_bn2hex(bn);
        BN_free(bn);
        if (!result) XSRETURN_UNDEF;
        XPUSHs(sv_2mortal(newSVpv((const char*)result, strlen(result))));
        OPENSSL_free(result);

void
P_ASN1_INTEGER_get_dec(i)
        ASN1_INTEGER * i
    INIT:
        BIGNUM *bn;
        char *result;
    PPCODE:
        bn = BN_new();
        if (!bn) XSRETURN_UNDEF;
        ASN1_INTEGER_to_BN(i, bn);
        result = BN_bn2dec(bn);
        BN_free(bn);
        if (!result) XSRETURN_UNDEF;
        XPUSHs(sv_2mortal(newSVpv((const char*)result, strlen(result))));
        OPENSSL_free(result);

void
P_ASN1_STRING_get(s,utf8_decode=0)
        ASN1_STRING * s
        int utf8_decode
    PREINIT:
        SV * u8;
    PPCODE:
        u8 = newSVpv((const char*)ASN1_STRING_data(s), ASN1_STRING_length(s));
        if (utf8_decode) sv_utf8_decode(u8);
        XPUSHs(sv_2mortal(u8));

ASN1_TIME *
X509_get_notBefore(cert)
     X509 *	cert

ASN1_TIME *
X509_get_notAfter(cert)
     X509 *	cert

ASN1_TIME *
X509_gmtime_adj(s, adj)
     ASN1_TIME * s
     long adj

ASN1_TIME *
ASN1_TIME_set(s,t)
     ASN1_TIME *s
     time_t t

void
ASN1_TIME_free(s)
     ASN1_TIME *s

ASN1_TIME *
ASN1_TIME_new()

void
P_ASN1_TIME_put2string(tm)
     ASN1_TIME * tm
     PREINIT:
     BIO *bp=NULL;
     int i=0;
     char buffer[256];
     ALIAS:
     P_ASN1_UTCTIME_put2string = 1
     CODE:
     ST(0) = sv_newmortal(); /* undef retval to start with */
     if (tm) {
         bp = BIO_new(BIO_s_mem());
         if (bp) {
             ASN1_TIME_print(bp,tm);
             i = BIO_read(bp,buffer,255);
             buffer[i] = '\0';
             if (i>0)
                 sv_setpvn(ST(0), buffer, i);
             BIO_free(bp);
         }
     }

#if OPENSSL_VERSION_NUMBER >= 0x0090705f
#define REM15 "NOTE: requires 0.9.7e+"

void
P_ASN1_TIME_get_isotime(tm)
     ASN1_TIME *tm
     PREINIT:
     ASN1_GENERALIZEDTIME *tmp = NULL;
     char buf[256];
     CODE:
     buf[0] = '\0';
     /* ASN1_TIME_to_generalizedtime is buggy on pre-0.9.7e */
     ASN1_TIME_to_generalizedtime(tm,&tmp);
     if (tmp) {
       if (ASN1_GENERALIZEDTIME_check(tmp)) {
         if (strlen((char*)tmp->data)>=14 && strlen((char*)tmp->data)<200) {
           strcpy (buf,"yyyy-mm-ddThh:mm:ss");
           strncpy(buf,   (char*)tmp->data,   4);
           strncpy(buf+5, (char*)tmp->data+4, 2);
           strncpy(buf+8, (char*)tmp->data+6, 2);
           strncpy(buf+11,(char*)tmp->data+8, 2);
           strncpy(buf+14,(char*)tmp->data+10,2);
           strncpy(buf+17,(char*)tmp->data+12,2);
           if (strlen((char*)tmp->data)>14) strcat(buf+19,(char*)tmp->data+14);
         }
       }
       ASN1_GENERALIZEDTIME_free(tmp);
     }
     ST(0) = sv_newmortal();
     sv_setpv(ST(0), buf);

void
P_ASN1_TIME_set_isotime(tm,str)
     ASN1_TIME *tm
     const char *str
     PREINIT:
     ASN1_TIME t;
     char buf[256];
     int i,rv;
     CODE:
     if (!tm) XSRETURN_UNDEF;
     /* we support only "2012-03-22T23:55:33" or "2012-03-22T23:55:33Z" or "2012-03-22T23:55:33<timezone>" */
     if (strlen(str) < 19) XSRETURN_UNDEF;
     for (i=0;  i<4;  i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     for (i=5;  i<7;  i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     for (i=8;  i<10; i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     for (i=11; i<13; i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     for (i=14; i<16; i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     for (i=17; i<19; i++) if ((str[i] > '9') || (str[i] < '0')) XSRETURN_UNDEF;
     strncpy(buf,    str,    4);
     strncpy(buf+4,  str+5,  2);
     strncpy(buf+6,  str+8,  2);
     strncpy(buf+8,  str+11, 2);
     strncpy(buf+10, str+14, 2);
     strncpy(buf+12, str+17, 2);
     buf[14] = '\0';
     if (strlen(str)>19 && strlen(str)<200) strcat(buf,str+19);

     /* WORKAROUND: ASN1_TIME_set_string() not available in 0.9.8 !!!*/
     /* in 1.0.0 we would simply: rv = ASN1_TIME_set_string(tm,buf); */
     t.length = strlen(buf);
     t.data = (unsigned char *)buf;
     t.flags = 0;
     t.type = V_ASN1_UTCTIME;
     if (!ASN1_TIME_check(&t)) {
        t.type = V_ASN1_GENERALIZEDTIME;
        if (!ASN1_TIME_check(&t)) XSRETURN_UNDEF;
     }
     tm->type = t.type;
     tm->flags = t.flags;
     if (!ASN1_STRING_set(tm,t.data,t.length)) XSRETURN_UNDEF;
     rv = 1;

     /* end of ASN1_TIME_set_string() reimplementation */

     ST(0) = sv_newmortal();
     sv_setiv(ST(0), rv); /* 1 = success, undef = failure */

#endif

int
EVP_PKEY_copy_parameters(to,from)
     EVP_PKEY *		to
     EVP_PKEY * 	from

EVP_PKEY *
EVP_PKEY_new()

void
EVP_PKEY_free(EVP_PKEY *pkey)

int
EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key)

int
EVP_PKEY_bits(EVP_PKEY *pkey)

int
EVP_PKEY_size(EVP_PKEY *pkey)

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL

int
EVP_PKEY_id(const EVP_PKEY *pkey)

#endif

void
PEM_get_string_X509(x509)
        X509 * x509
     PREINIT:
        BIO *bp;
        int i, n;
        char *buf;
     CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp && x509) {
            PEM_write_bio_X509(bp,x509);
            n = BIO_ctrl_pending(bp);
            New(0, buf, n, char);
            if (buf) {
                i = BIO_read(bp,buf,n);
                if (i>=0 && i<=n) sv_setpvn(ST(0), buf, i);
                Safefree(buf);
            }
            BIO_free(bp);
        }

void
PEM_get_string_X509_REQ(x509_req)
        X509_REQ * x509_req
    PREINIT:
        BIO *bp;
        int i, n;
        char *buf;
    CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp && x509_req) {
            PEM_write_bio_X509_REQ(bp,x509_req);
            n = BIO_ctrl_pending(bp);
            New(0, buf, n, char);
            if (buf) {
                i = BIO_read(bp,buf,n);
                if (i>=0 && i<=n) sv_setpvn(ST(0), buf, i);
                Safefree(buf);
            }
            BIO_free(bp);
        }

void
PEM_get_string_X509_CRL(x509_crl)
        X509_CRL * x509_crl
    PREINIT:
        BIO *bp;
        int i, n;
        char *buf;
    CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp && x509_crl) {
            PEM_write_bio_X509_CRL(bp,x509_crl);
            n = BIO_ctrl_pending(bp);
            New(0, buf, n, char);
            if (buf) {
                i = BIO_read(bp,buf,n);
                if (i>=0 && i<=n) sv_setpvn(ST(0), buf, i);
                Safefree(buf);
            }
            BIO_free(bp);
        }

void
PEM_get_string_PrivateKey(pk,passwd=NULL,enc_alg=NULL)
        EVP_PKEY * pk
        char * passwd
        const EVP_CIPHER * enc_alg
    PREINIT:
        BIO *bp;
        int i, n;
        char *buf;
        int passwd_len = 0;
        pem_password_cb * cb = NULL;
        void * u = NULL;
    CODE:
        ST(0) = sv_newmortal(); /* undef to start with */
        bp = BIO_new(BIO_s_mem());
        if (bp && pk) {
            if (passwd) passwd_len = strlen(passwd);
            if (passwd_len>0) {
                /* encrypted key */
                if (!enc_alg)
                    PEM_write_bio_PrivateKey(bp,pk,EVP_des_cbc(),(unsigned char *)passwd,passwd_len,cb,u);
                else
                    PEM_write_bio_PrivateKey(bp,pk,enc_alg,(unsigned char *)passwd,passwd_len,cb,u);
            }
            else {
                /* unencrypted key */
                PEM_write_bio_PrivateKey(bp,pk,NULL,(unsigned char *)passwd,passwd_len,cb,u);
            }
            n = BIO_ctrl_pending(bp);
            New(0, buf, n, char);
            if (buf) {
                i = BIO_read(bp,buf,n);
                if (i>=0 && i<=n) sv_setpvn(ST(0), buf, i);
                Safefree(buf);
            }
            BIO_free(bp);
        }

int
CTX_use_PKCS12_file(ctx, file, password=NULL)
        SSL_CTX *ctx
        char *file
        char *password
    PREINIT:
        PKCS12 *p12;
        EVP_PKEY *private_key;
        X509 *certificate;
        FILE *fp;
    CODE:
        RETVAL = 0;
        if ((fp = fopen (file, "rb"))) {
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
            OPENSSL_add_all_algorithms_noconf();
#else
            OpenSSL_add_all_algorithms();
#endif
            if ((p12 = d2i_PKCS12_fp(fp, NULL))) {
                if (PKCS12_parse(p12, password, &private_key, &certificate, NULL)) {
                    if (private_key) {
                        if (SSL_CTX_use_PrivateKey(ctx, private_key)) RETVAL = 1;
                        EVP_PKEY_free(private_key);
                    }
                    if (certificate) {
                        if (SSL_CTX_use_certificate(ctx, certificate)) RETVAL = 1;
                        X509_free(certificate);
                    }
                }
                PKCS12_free(p12);
            }
            if (!RETVAL) ERR_print_errors_fp(stderr);
            fclose(fp);
        }
    OUTPUT:
        RETVAL

void
P_PKCS12_load_file(file, load_chain=0, password=NULL)
        char *file
        int load_chain
        char *password
    PREINIT:
        PKCS12 *p12;
        EVP_PKEY *private_key = NULL;
        X509 *certificate = NULL;
        STACK_OF(X509) *cachain = NULL;
        X509 *x;
        FILE *fp;
        int i, result;
    PPCODE:
        if ((fp = fopen (file, "rb"))) {
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
            OPENSSL_add_all_algorithms_noconf();
#else
            OpenSSL_add_all_algorithms();
#endif
            if ((p12 = d2i_PKCS12_fp(fp, NULL))) {
                if(load_chain)
                    result= PKCS12_parse(p12, password, &private_key, &certificate, &cachain);
                else
                    result= PKCS12_parse(p12, password, &private_key, &certificate, NULL);
                if (result) {
                    if (private_key)
                        XPUSHs(sv_2mortal(newSViv(PTR2IV(private_key))));
                    else
                        XPUSHs(sv_2mortal(newSVpv(NULL,0))); /* undef */
                    if (certificate)
                        XPUSHs(sv_2mortal(newSViv(PTR2IV(certificate))));
                    else
                        XPUSHs(sv_2mortal(newSVpv(NULL,0))); /* undef */
                    if (cachain) {
                        for (i=0; i<sk_X509_num(cachain); i++) {
                            x = sk_X509_value(cachain, i);
                            XPUSHs(sv_2mortal(newSViv(PTR2IV(x))));
                        }
                        sk_X509_free(cachain);
                    }
                }
                PKCS12_free(p12);
            }
            fclose(fp);
        }

#ifndef OPENSSL_NO_MD2

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

#endif

void
MD4(data)
	PREINIT:
	STRLEN len;
	unsigned char md[MD4_DIGEST_LENGTH];
	INPUT:
	unsigned char* data = (unsigned char *) SvPV( ST(0), len );
	CODE:
	if (MD4(data,len,md)) {
		XSRETURN_PVN((char *) md, MD4_DIGEST_LENGTH);
	} else {
		XSRETURN_UNDEF;
	}

void
MD5(data)
     PREINIT:
     STRLEN len;
     unsigned char md[MD5_DIGEST_LENGTH];
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     if (MD5(data,len,md)) {
	  XSRETURN_PVN((char *) md, MD5_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

#if OPENSSL_VERSION_NUMBER >= 0x00905000L

void
RIPEMD160(data)
     PREINIT:
     STRLEN len;
     unsigned char md[RIPEMD160_DIGEST_LENGTH];
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     if (RIPEMD160(data,len,md)) {
	  XSRETURN_PVN((char *) md, RIPEMD160_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

#endif

#if !defined(OPENSSL_NO_SHA)

void
SHA1(data)
     PREINIT:
     STRLEN len;
     unsigned char md[SHA_DIGEST_LENGTH];
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     if (SHA1(data,len,md)) {
	  XSRETURN_PVN((char *) md, SHA_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

#endif
#if !defined(OPENSSL_NO_SHA256) && OPENSSL_VERSION_NUMBER >= 0x0090800fL

void
SHA256(data)
     PREINIT:
     STRLEN len;
     unsigned char md[SHA256_DIGEST_LENGTH];
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     if (SHA256(data,len,md)) {
	  XSRETURN_PVN((char *) md, SHA256_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

#endif
#if !defined(OPENSSL_NO_SHA512) && OPENSSL_VERSION_NUMBER >= 0x0090800fL

void
SHA512(data)
     PREINIT:
     STRLEN len;
     unsigned char md[SHA512_DIGEST_LENGTH];
     INPUT:
     unsigned char *  data = (unsigned char *) SvPV( ST(0), len);
     CODE:
     if (SHA512(data,len,md)) {
	  XSRETURN_PVN((char *) md, SHA512_DIGEST_LENGTH);
     } else {
	  XSRETURN_UNDEF;
     }

#endif

#ifndef OPENSSL_NO_SSL2
#if OPENSSL_VERSION_NUMBER < 0x10000000L

const SSL_METHOD *
SSLv2_method()

#endif
#endif

const SSL_METHOD *
SSLv3_method()

const SSL_METHOD *
TLSv1_method()

#if OPENSSL_VERSION_NUMBER < 0x10000000L

int
SSL_set_ssl_method(ssl, method)
     SSL *         ssl
     SSL_METHOD *  method

#else

int
SSL_set_ssl_method(ssl, method)
     SSL *               ssl
     const SSL_METHOD *  method

#endif

const SSL_METHOD *
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
	New(0, buf, max, char);
	ST(0) = sv_newmortal();   /* Undefined to start with */
	if ((got = BIO_read(s, buf, max)) >= 0)
		sv_setpvn( ST(0), buf, got);
	Safefree(buf);

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

#if OPENSSL_VERSION_NUMBER < 0x009080dfL
#define REM8 "NOTE: before 0.9.8m"

char *
SSL_CIPHER_description(cipher,buf,size)
     SSL_CIPHER *	cipher
     char *	buf
     int 	size

#else

char *
SSL_CIPHER_description(cipher,buf,size)
     const SSL_CIPHER *  cipher
     char *	buf
     int 	size

#endif

#if OPENSSL_VERSION_NUMBER < 0x0090707fL
#define REM9 "NOTE: before 0.9.7g"

const char *
SSL_CIPHER_get_name(SSL_CIPHER *c)

int
SSL_CIPHER_get_bits(c,alg_bits=NULL)
     SSL_CIPHER *	c
     int *	alg_bits

#else

const char *
SSL_CIPHER_get_name(const SSL_CIPHER *c)

int
SSL_CIPHER_get_bits(c,alg_bits=NULL)
     const SSL_CIPHER *	c
     int *	alg_bits

#endif

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
SSL_CTX_set_cert_verify_callback(ctx,callback,data=&PL_sv_undef)
        SSL_CTX * ctx
        SV * callback
        SV * data
    CODE: 
        if (callback==NULL || !SvOK(callback)) {
            SSL_CTX_set_cert_verify_callback(ctx, NULL, NULL);
            cb_data_advanced_put(ctx, "ssleay_ctx_cert_verify_cb!!func", NULL);
            cb_data_advanced_put(ctx, "ssleay_ctx_cert_verify_cb!!data", NULL);
        }
        else {
            cb_data_advanced_put(ctx, "ssleay_ctx_cert_verify_cb!!func", newSVsv(callback));
            cb_data_advanced_put(ctx, "ssleay_ctx_cert_verify_cb!!data", newSVsv(data));
#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
            SSL_CTX_set_cert_verify_callback(ctx, ssleay_ctx_cert_verify_cb_invoke, ctx);
#else
            SSL_CTX_set_cert_verify_callback(ctx, ssleay_ctx_cert_verify_cb_invoke, (char*)ctx);
#endif
        }

X509_NAME_STACK *
SSL_CTX_get_client_CA_list(ctx)
	SSL_CTX *ctx

void
SSL_CTX_set_client_CA_list(ctx,list)
     SSL_CTX *	ctx
     X509_NAME_STACK * list

void
SSL_CTX_set_default_passwd_cb(ctx,callback=&PL_sv_undef)
        SSL_CTX * ctx
        SV * callback
    CODE:
        if (callback==NULL || !SvOK(callback)) {
            SSL_CTX_set_default_passwd_cb(ctx, NULL);
            SSL_CTX_set_default_passwd_cb_userdata(ctx, NULL);
            cb_data_advanced_put(ctx, "ssleay_ctx_passwd_cb!!func", NULL);
        }
        else {
            cb_data_advanced_put(ctx, "ssleay_ctx_passwd_cb!!func", newSVsv(callback));
            SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)ctx);
            SSL_CTX_set_default_passwd_cb(ctx, &ssleay_ctx_passwd_cb_invoke);
        }

void 
SSL_CTX_set_default_passwd_cb_userdata(ctx,data=&PL_sv_undef)
        SSL_CTX * ctx
        SV * data
    CODE:
        /* SSL_CTX_set_default_passwd_cb_userdata is set in SSL_CTX_set_default_passwd_cb */
        if (data==NULL || !SvOK(data)) {
            cb_data_advanced_put(ctx, "ssleay_ctx_passwd_cb!!data", NULL);
        }
        else {
            cb_data_advanced_put(ctx, "ssleay_ctx_passwd_cb!!data", newSVsv(data));
        }

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

#if OPENSSL_VERSION_NUMBER < 0x10000000L

int
SSL_CTX_set_ssl_version(ctx,meth)
     SSL_CTX *	ctx
     SSL_METHOD *	meth

#else

int
SSL_CTX_set_ssl_version(ctx,meth)
     SSL_CTX *	ctx
     const SSL_METHOD *	meth

#endif

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

const SSL_CIPHER *
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

#if OPENSSL_VERSION_NUMBER < 0x10000000L

int
SSL_SESSION_cmp(a,b)
     SSL_SESSION *	a
     SSL_SESSION *	b

#endif

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
sk_X509_NAME_free(sk)
	X509_NAME_STACK *sk

int
sk_X509_NAME_num(sk)
	X509_NAME_STACK *sk

X509_NAME *
sk_X509_NAME_value(sk,i)
	X509_NAME_STACK *sk
	int i

X509_NAME_STACK *
SSL_get_client_CA_list(s)
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
     cb_ssl_int_int_ret_void *  cb

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
SSL_get_cipher_bits(s,np=NULL)
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
     DH *	dh

long
SSL_set_tmp_rsa(ssl,rsa)
     SSL *	ssl
     char *	rsa
  CODE:
  RETVAL = SSL_ctrl(ssl,SSL_CTRL_SET_TMP_RSA,0,(char *)rsa);
  OUTPUT:
  RETVAL

RSA *
RSA_generate_key(bits,e,perl_cb=&PL_sv_undef,perl_data=&PL_sv_undef)
        int bits
        unsigned long e
        SV* perl_cb
        SV* perl_data
    PREINIT:
        simple_cb_data_t* cb = NULL;
    CODE:
        cb = simple_cb_data_new(perl_cb, perl_data);
        RETVAL = RSA_generate_key(bits, e, ssleay_RSA_generate_key_cb_invoke, cb);
        simple_cb_data_free(cb);
    OUTPUT:
        RETVAL

void
RSA_free(r)
    RSA * r

X509 *
X509_new()

void
X509_free(a)
    X509 * a

X509_CRL *
d2i_X509_CRL_bio(BIO *bp,void *unused=NULL)

X509_REQ *
d2i_X509_REQ_bio(BIO *bp,void *unused=NULL)

X509 *
d2i_X509_bio(BIO *bp,void *unused=NULL)

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

X509 *
PEM_read_bio_X509(BIO *bio,void *x=NULL,void *cb=NULL,void *u=NULL)

X509_REQ *
PEM_read_bio_X509_REQ(BIO *bio,void *x=NULL,pem_password_cb *cb=NULL,void *u=NULL)

EVP_PKEY *
PEM_read_bio_PrivateKey(bio,perl_cb=&PL_sv_undef,perl_data=&PL_sv_undef)
        BIO *bio
        SV* perl_cb
        SV* perl_data
    PREINIT:
        simple_cb_data_t* cb = NULL;
    CODE:
        RETVAL = 0;
        if (SvOK(perl_cb)) {
            /* setup our callback */
            cb = simple_cb_data_new(perl_cb, perl_data);
            RETVAL = PEM_read_bio_PrivateKey(bio, NULL, pem_password_cb_invoke, (void*)cb);
            simple_cb_data_free(cb);
        }
        else if (!SvOK(perl_cb) && SvOK(perl_data) && SvPOK(perl_data)) {
            /* use perl_data as the password */
            RETVAL = PEM_read_bio_PrivateKey(bio, NULL, NULL, SvPVX(perl_data));
        }
        else if (!SvOK(perl_cb) && !SvOK(perl_data)) {
            /* will trigger default password callback */
            RETVAL = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        }
    OUTPUT:
        RETVAL

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
SSL_SESSION_set_master_key(s,key)
     SSL_SESSION *   s
     PREINIT:
     STRLEN len;
     INPUT:
     char * key = SvPV(ST(1), len);
     CODE:
     memcpy(s->master_key, key, len);
     s->master_key_length = len;

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

int
SSL_get_keyblock_size(s)
     SSL *   s
     CODE:
     if (s == NULL ||
	 s->enc_read_ctx == NULL ||
	 s->enc_read_ctx->cipher == NULL ||
	 s->read_hash == NULL)
     {
	RETVAL = -1;
     }
     else
     {
	const EVP_CIPHER *c;
	const EVP_MD *h;
	c = s->enc_read_ctx->cipher;
#if OPENSSL_VERSION_NUMBER >= 0x00909000L
	h = EVP_MD_CTX_md(s->read_hash);
#else
	h = s->read_hash;
#endif

	RETVAL = 2 * (EVP_CIPHER_key_length(c) +
		    EVP_MD_size(h) +
		    EVP_CIPHER_iv_length(c));
     }
     OUTPUT:
     RETVAL



#if defined(SSL_F_SSL_SET_HELLO_EXTENSION)
int
SSL_set_hello_extension(s, type, data)
     SSL *   s
     int     type
     PREINIT:
     STRLEN len;
     INPUT:
     char *  data = SvPV( ST(2), len);
     CODE:
     RETVAL = SSL_set_hello_extension(s, type, data, len);
     OUTPUT:
     RETVAL

#endif

#if defined(SSL_F_SSL_SET_HELLO_EXTENSION) || defined(SSL_F_SSL_SET_SESSION_TICKET_EXT)

void 
SSL_set_session_secret_cb(s,callback=&PL_sv_undef,data=&PL_sv_undef)
        SSL * s
        SV * callback
        SV * data
    CODE:
        if (callback==NULL || !SvOK(callback)) {
            SSL_set_session_secret_cb(s, NULL, NULL);
            cb_data_advanced_put(s, "ssleay_session_secret_cb!!func", NULL);
            cb_data_advanced_put(s, "ssleay_session_secret_cb!!data", NULL);
        }
        else {
            cb_data_advanced_put(s, "ssleay_session_secret_cb!!func", newSVsv(callback));
            cb_data_advanced_put(s, "ssleay_session_secret_cb!!data", newSVsv(data));
            SSL_set_session_secret_cb(s, (int (*)(SSL *s, void *secret, int *secret_len,
                STACK_OF(SSL_CIPHER) *peer_ciphers,
                SSL_CIPHER **cipher, void *arg))&ssleay_session_secret_cb_invoke, s);
        }

#endif

#if OPENSSL_VERSION_NUMBER < 0x0090700fL
#define REM11 "NOTE: before 0.9.7"

int EVP_add_digest(EVP_MD *digest)

#else

int EVP_add_digest(const EVP_MD *digest)

#endif

#ifndef OPENSSL_NO_SHA

const EVP_MD *EVP_sha1()

#endif
#if !defined(OPENSSL_NO_SHA256) && OPENSSL_VERSION_NUMBER >= 0x0090800fL

const EVP_MD *EVP_sha256()

#endif
#if !defined(OPENSSL_NO_SHA512) && OPENSSL_VERSION_NUMBER >= 0x0090800fL

const EVP_MD *EVP_sha512()

#endif
void OpenSSL_add_all_digests()

const EVP_MD * EVP_get_digestbyname(const char *name)

int EVP_MD_type(const EVP_MD *md)

int EVP_MD_size(const EVP_MD *md)

#if OPENSSL_VERSION_NUMBER >= 0x1000000fL

SV*
P_EVP_MD_list_all()
    INIT:
        AV * results;
    CODE:
        results = (AV *)sv_2mortal((SV *)newAV());
        EVP_MD_do_all_sorted(handler_list_md_fn, results);
        RETVAL = newRV((SV *)results);
    OUTPUT:
        RETVAL

#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL
#define REM16 "NOTE: requires 0.9.7+"

const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx)

EVP_MD_CTX *EVP_MD_CTX_create()

int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type)

int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)

void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx)

void
EVP_DigestUpdate(ctx,data)
     PREINIT:
     STRLEN len;
     INPUT:
     EVP_MD_CTX *ctx = INT2PTR(EVP_MD_CTX *, SvIV(ST(0)));
     unsigned char *data = (unsigned char *) SvPV(ST(1), len);
     CODE:
     XSRETURN_IV(EVP_DigestUpdate(ctx,data,len));

void
EVP_DigestFinal(ctx)
     EVP_MD_CTX *ctx
     INIT:
     unsigned char md[EVP_MAX_MD_SIZE];
     unsigned int md_size;
     CODE:
     if (EVP_DigestFinal(ctx,md,&md_size))
         XSRETURN_PVN((char *)md, md_size);
     else
         XSRETURN_UNDEF;

void
EVP_DigestFinal_ex(ctx)
     EVP_MD_CTX *ctx
     INIT:
     unsigned char md[EVP_MAX_MD_SIZE];
     unsigned int md_size;
     CODE:
     if (EVP_DigestFinal_ex(ctx,md,&md_size))
         XSRETURN_PVN((char *)md, md_size);
     else
         XSRETURN_UNDEF;

void
EVP_Digest(...)
     PREINIT:
     STRLEN len;
     unsigned char md[EVP_MAX_MD_SIZE];
     unsigned int md_size;
     INPUT:
     unsigned char *data = (unsigned char *) SvPV(ST(0), len);
     EVP_MD *type = INT2PTR(EVP_MD *, SvIV(ST(1)));
     ENGINE *impl = (items>2 && SvOK(ST(2))) ? INT2PTR(ENGINE *, SvIV(ST(2))) : NULL;
     CODE:
     if (EVP_Digest(data,len,md,&md_size,type,impl))
         XSRETURN_PVN((char *)md, md_size);
     else
         XSRETURN_UNDEF;

#endif

const EVP_CIPHER *
EVP_get_cipherbyname(const char *name)

void
OpenSSL_add_all_algorithms()

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL

void
OPENSSL_add_all_algorithms_noconf()

void
OPENSSL_add_all_algorithms_conf()

#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000L

int
SSL_CTX_set1_param(ctx, vpm)
     SSL_CTX *          ctx
     X509_VERIFY_PARAM *vpm

int
SSL_set1_param(ctx, vpm)
     SSL *          ctx
     X509_VERIFY_PARAM *vpm

#endif

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL

X509_VERIFY_PARAM *
X509_VERIFY_PARAM_new()

void
X509_VERIFY_PARAM_free(param)
     X509_VERIFY_PARAM *param

int
X509_VERIFY_PARAM_inherit(to, from)
     X509_VERIFY_PARAM *to
     X509_VERIFY_PARAM *from

int
X509_VERIFY_PARAM_set1(to, from)
     X509_VERIFY_PARAM *to
     X509_VERIFY_PARAM *from

int
X509_VERIFY_PARAM_set1_name(param, name)
     X509_VERIFY_PARAM *param
     const char *name

int
X509_VERIFY_PARAM_set_flags(param, flags)
    X509_VERIFY_PARAM *param
    unsigned long flags

#if OPENSSL_VERSION_NUMBER >= 0x0090801fL
#define REM13 "NOTE: requires 0.9.8a+"

int
X509_VERIFY_PARAM_clear_flags(param, flags)
    X509_VERIFY_PARAM *param
    unsigned long flags

unsigned long
X509_VERIFY_PARAM_get_flags(param)
     X509_VERIFY_PARAM *param

#endif

int
X509_VERIFY_PARAM_set_purpose(param, purpose)
    X509_VERIFY_PARAM *param
    int purpose

int
X509_VERIFY_PARAM_set_trust(param, trust)
    X509_VERIFY_PARAM *param
    int trust

void
X509_VERIFY_PARAM_set_depth(param, depth)
    X509_VERIFY_PARAM *param
    int depth

void
X509_VERIFY_PARAM_set_time(param, t)
    X509_VERIFY_PARAM *param
    time_t t

int
X509_VERIFY_PARAM_add0_policy(param, policy)
    X509_VERIFY_PARAM *param
    ASN1_OBJECT *policy

int
X509_VERIFY_PARAM_set1_policies(param, policies)
    X509_VERIFY_PARAM *param
    STACK_OF(ASN1_OBJECT) *policies

int
X509_VERIFY_PARAM_get_depth(param)
    X509_VERIFY_PARAM *param

int
X509_VERIFY_PARAM_add0_table(param)
    X509_VERIFY_PARAM *param

const X509_VERIFY_PARAM *
X509_VERIFY_PARAM_lookup(name)
    const char *name

void
X509_VERIFY_PARAM_table_cleanup()

void
X509_policy_tree_free(tree)
    X509_POLICY_TREE *tree

int
X509_policy_tree_level_count(tree)
    X509_POLICY_TREE *tree

X509_POLICY_LEVEL *
X509_policy_tree_get0_level(tree, i)
    X509_POLICY_TREE *tree
    int i

STACK_OF(X509_POLICY_NODE) *
X509_policy_tree_get0_policies(tree)
    X509_POLICY_TREE *tree

STACK_OF(X509_POLICY_NODE) *
X509_policy_tree_get0_user_policies(tree)
    X509_POLICY_TREE *tree

int
X509_policy_level_node_count(level)
    X509_POLICY_LEVEL *level

X509_POLICY_NODE *
X509_policy_level_get0_node(level, i)
    X509_POLICY_LEVEL *level
    int i

const ASN1_OBJECT *
X509_policy_node_get0_policy(node)
    const X509_POLICY_NODE *node

STACK_OF(POLICYQUALINFO) *
X509_policy_node_get0_qualifiers(node)
    X509_POLICY_NODE *node

const X509_POLICY_NODE *
X509_policy_node_get0_parent(node)
    const X509_POLICY_NODE *node

#endif

ASN1_OBJECT *
OBJ_dup(o)
    ASN1_OBJECT *o

ASN1_OBJECT *
OBJ_nid2obj(n)
    int n

const char *
OBJ_nid2ln(n)
    int n

const char *
OBJ_nid2sn(n)
    int n

int
OBJ_obj2nid(o)
    ASN1_OBJECT *o

ASN1_OBJECT *
OBJ_txt2obj(s, no_name=0)
    const char *s
    int no_name

void
OBJ_obj2txt(a, no_name=0)
    ASN1_OBJECT *a
    int no_name
    PREINIT:
    char buf[100]; /* openssl doc: a buffer length of 80 should be more than enough to handle any OID encountered in practice */
    int  len;
    CODE:
    len = OBJ_obj2txt(buf, sizeof(buf), a, no_name);
    ST(0) = sv_newmortal();
    sv_setpvn(ST(0), buf, len);

#if OPENSSL_VERSION_NUMBER < 0x0090700fL
#define REM14 "NOTE: before 0.9.7"

int
OBJ_txt2nid(s)
    char *s

#else

int
OBJ_txt2nid(s)
    const char *s

#endif

int
OBJ_ln2nid(s)
    const char *s

int
OBJ_sn2nid(s)
    const char *s

int
OBJ_cmp(a, b)
    ASN1_OBJECT *a
    ASN1_OBJECT *b

#if OPENSSL_VERSION_NUMBER >= 0x0090700fL

void
X509_pubkey_digest(data,type)
        const X509 *data
        const EVP_MD *type
    PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_size;
    PPCODE:
        if (X509_pubkey_digest(data,type,md,&md_size))
            XSRETURN_PVN((char *)md, md_size);
        else
            XSRETURN_UNDEF;

#endif

void
X509_digest(data,type)
        const X509 *data
        const EVP_MD *type
    PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_size;
    PPCODE:
        if (X509_digest(data,type,md,&md_size))
            XSRETURN_PVN((char *)md, md_size);
        XSRETURN_UNDEF;

void
X509_CRL_digest(data,type)
        const X509_CRL *data
        const EVP_MD *type
    PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_size;
    PPCODE:
        if (X509_CRL_digest(data,type,md,&md_size))
            XSRETURN_PVN((char *)md, md_size);
        XSRETURN_UNDEF;

void
X509_REQ_digest(data,type)
        const X509_REQ *data
        const EVP_MD *type
    PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_size;
    PPCODE:
        if (X509_REQ_digest(data,type,md,&md_size))
            XSRETURN_PVN((char *)md, md_size);
        XSRETURN_UNDEF;

void
X509_NAME_digest(data,type)
        const X509_NAME *data
        const EVP_MD *type
    PREINIT:
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_size;
    PPCODE:
        if (X509_NAME_digest(data,type,md,&md_size))
            XSRETURN_PVN((char *)md, md_size);
        XSRETURN_UNDEF;

unsigned long
X509_subject_name_hash(X509 *x)

unsigned long
X509_issuer_name_hash(X509 *a)

unsigned long
X509_issuer_and_serial_hash(X509 *a)

ASN1_OBJECT *
P_X509_get_signature_alg(x)
        X509 * x
    CODE:
        RETVAL = (x->cert_info->signature->algorithm);
    OUTPUT:
        RETVAL

ASN1_OBJECT *
P_X509_get_pubkey_alg(x)
        X509 * x
    CODE:
        RETVAL = (x->cert_info->key->algor->algorithm);
    OUTPUT:
        RETVAL

#if OPENSSL_VERSION_NUMBER >= 0x10001000L && !defined(OPENSSL_NO_NEXTPROTONEG)

int
SSL_CTX_set_next_protos_advertised_cb(ctx,callback,data=&PL_sv_undef)
        SSL_CTX * ctx
        SV * callback
        SV * data
    CODE:
        RETVAL = 1;
        if (callback==NULL || !SvOK(callback)) {
            SSL_CTX_set_next_protos_advertised_cb(ctx, NULL, NULL);
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!func", NULL);
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!data", NULL);
            PR1("SSL_CTX_set_next_protos_advertised_cb - undef\n");
        }
        else if (SvROK(callback) && (SvTYPE(SvRV(callback)) == SVt_PVAV)) {
            /* callback param array ref like ['proto1','proto2'] */
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!func", NULL);
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!data", newSVsv(callback));
            SSL_CTX_set_next_protos_advertised_cb(ctx, next_protos_advertised_cb_invoke, ctx);
            PR2("SSL_CTX_set_next_protos_advertised_cb - simple ctx=%p\n",ctx);
        }
        else if (SvROK(callback) && (SvTYPE(SvRV(callback)) == SVt_PVCV)) {
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!func", newSVsv(callback));
            cb_data_advanced_put(ctx, "next_protos_advertised_cb!!data", newSVsv(data));
            SSL_CTX_set_next_protos_advertised_cb(ctx, next_protos_advertised_cb_invoke, ctx);
            PR2("SSL_CTX_set_next_protos_advertised_cb - advanced ctx=%p\n",ctx);
        }
        else {
            RETVAL = 0;
        }
    OUTPUT:
        RETVAL

int
SSL_CTX_set_next_proto_select_cb(ctx,callback,data=&PL_sv_undef)
        SSL_CTX * ctx
        SV * callback
        SV * data
    CODE: 
        RETVAL = 1;
        if (callback==NULL || !SvOK(callback)) {
            SSL_CTX_set_next_proto_select_cb(ctx, NULL, NULL);
            cb_data_advanced_put(ctx, "next_proto_select_cb!!func", NULL);
            cb_data_advanced_put(ctx, "next_proto_select_cb!!data", NULL);
            PR1("SSL_CTX_set_next_proto_select_cb - undef\n");
        }
        else if (SvROK(callback) && (SvTYPE(SvRV(callback)) == SVt_PVAV)) {
            /* callback param array ref like ['proto1','proto2'] */
            cb_data_advanced_put(ctx, "next_proto_select_cb!!func", NULL);
            cb_data_advanced_put(ctx, "next_proto_select_cb!!data", newSVsv(callback));
            SSL_CTX_set_next_proto_select_cb(ctx, next_proto_select_cb_invoke, ctx);
            PR2("SSL_CTX_set_next_proto_select_cb - simple ctx=%p\n",ctx);
        }
        else if (SvROK(callback) && (SvTYPE(SvRV(callback)) == SVt_PVCV)) {
            cb_data_advanced_put(ctx, "next_proto_select_cb!!func", newSVsv(callback));
            cb_data_advanced_put(ctx, "next_proto_select_cb!!data", newSVsv(data));
            SSL_CTX_set_next_proto_select_cb(ctx, next_proto_select_cb_invoke, ctx);
            PR2("SSL_CTX_set_next_proto_select_cb - advanced ctx=%p\n",ctx);
        }
        else {
            RETVAL = 0;
        }
    OUTPUT:
        RETVAL

void
P_next_proto_negotiated(s)
        const SSL *s
    PREINIT:
        const unsigned char *data;
        unsigned int len;
    PPCODE:
        SSL_get0_next_proto_negotiated(s, &data, &len);
        XPUSHs(sv_2mortal(newSVpv((char *)data, len)));

void
P_next_proto_last_status(s)
        const SSL *s
    PPCODE:
        XPUSHs(sv_2mortal(newSVsv(cb_data_advanced_get((void*)s, "next_proto_select_cb!!last_status"))));

#endif

#define REM_EOF "/* EOF - SSLeay.xs */"
