/*
 * coap_wolfssl.c -- Datagram Transport Layer Support for libcoap with wolfssl
 *
 * Copyright (C) 2017      Jean-Claude Michelou <jcm@spinetix.com>
 * Copyright (C) 2018-2023 Jon Shallow <supjps-libcoap@jpshallow.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */

/**
 * @file coap_wolfssl.c
 * @brief wolfSSL specific interface functions.
 */

#include "coap3/coap_internal.h"


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wcast-qual"

#ifdef COAP_WITH_LIBWOLFSSL

/*
 * Implemented using wolfSSL's OpenSSL compatibility layer based on coap_openssl.c.
 *
 * It is possible to override the Ciphers, define the Algorithms or Groups
 * to use for the SSL negotiations at compile time. This is done by the adding
 * of the appropriate -D option to the CPPFLAGS parameter that is used on the
 * ./configure command line.
 * E.g.  ./configure CPPFLAGS="-DXX=\"YY\" -DUU=\"VV\""
 * The parameter value is case-sensitive.
 *
 * The ciphers can be overridden with (example)
 *  CPPFLAGS="-DCOAP_WOLFSSL_CIPHERS=\"\\\"TLS13-AES128-GCM-SHA256\\\"\""
 *
 * The Algorithms can be defined by (example)
 *  CPPFLAGS="-DCOAP_WOLFSSL_SIGALGS=\"\\\"RSA+SHA256\\\"\""
 *
 * The Groups (including post-quantum ones, if wolfSSL has been built with liboqs
 * and DTLS 1.3 enabled) can be defined using the following example:
 *  CPPFLAGS="-DCOAP_WOLFSSL_GROUPS=\"\\\"P-384:P-256:KYBER_LEVEL1\\\"\"" ./configure ...
 *
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509v3.h>

#ifdef COAP_EPOLL_SUPPORT
# include <sys/epoll.h>
#endif /* COAP_EPOLL_SUPPORT */

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#endif

/* TODO: link free parameters */
#define IS_DTLS13 1
#define HRR_COOKIE 1
#define USE_SECURE_RENEGOTIATION 0

#ifndef WOLFSSL_DTLS13
#define IS_DTLS13 0
#endif

#ifndef WOLFSSL_DEBUG
#define WOLFSSL_DEBUG 0
#endif

#if IS_DTLS13 == 1
#define USE_SECURE_RENEGOTIATION 0
#ifndef WOLFSSL_SEND_HRR_COOKIE
#define HRR_COOKIE 0
#endif
#else
#define HRR_COOKIE 0
#ifndef HAVE_SECURE_RENEGOTIATION
#define USE_SECURE_RENEGOTIATION 0
#endif
#endif

/* RFC6091/RFC7250 */
#ifndef TLSEXT_TYPE_client_certificate_type
#define TLSEXT_TYPE_client_certificate_type 19
#endif
#ifndef TLSEXT_TYPE_server_certificate_type
#define TLSEXT_TYPE_server_certificate_type 20
#endif

#ifndef COAP_WOLFSSL_CIPHERS
#define COAP_WOLFSSL_CIPHERS "TLS13-AES128-GCM-SHA256"
#endif /*COAP_WOLFSSL_CIPHERS */

#ifndef COAP_WOLFSSL_PSK_CIPHERS
#define COAP_WOLFSSL_PSK_CIPHERS "PSK:!NULL"
#endif /*COAP_WOLFSSL_PSK_CIPHERS */

// definitions inspired on compatibility layer
#define wolfSSL_BIO_set_retry_read(a) wolfSSL_BIO_set_flags((a), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_READ)
#define wolfSSL_BIO_set_retry_write(a) wolfSSL_BIO_set_flags((a), WOLFSSL_BIO_FLAG_RETRY | WOLFSSL_BIO_FLAG_WRITE)
#define wolfSSL_CTX_get_app_data(ctx) wolfSSL_CTX_get_ex_data(ctx, 0)
#define wolfSSL_CTX_set_app_data(ctx, arg) wolfSSL_CTX_set_ex_data(ctx, 0, (char *)(arg))

// missing definitions
#define WOLFSSL_EVP_GCM_TLS_EXPLICIT_IV_LEN 8
#define WOLFSSL_EVP_GCM_TLS_TAG_LEN 16
#define WOLFSSL_EVP_CCM_TLS_EXPLICIT_IV_LEN 8

#define WOLFSSL3_AL_FATAL 2
#define WOLFSSL_TLSEXT_ERR_OK 0

#define WOLFSSL_DTLS13_RT_HEADER_LENGTH 13

#define COAP_BIO_TYPE_DGRAM 0x90  // Custom type code for Datagram
#define COAP_BIO_TYPE_SOCKET 0x91 // Custom type code for Socket

static char *
wolfSSL_strdup(const char *str) {
  char *ret = (char *)XMALLOC(strlen(str) + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  if (ret) {
    strcpy(ret, str);
  }
  return ret;
}

static char *
wolfSSL_strndup(const char *str, size_t n) {
  size_t len = strnlen(str, n);
  char *ret = (char *)XMALLOC(len + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
  if (ret) {
    strncpy(ret, str, len);
    ret[len] = '\0';
  }
  return ret;
}

/* This structure encapsulates the wolfSSL context object. */
typedef struct coap_dtls_context_t {
  WOLFSSL_CTX *ctx;
  WOLFSSL *ssl;
  WOLFSSL_HMAC_CTX *cookie_hmac;
  WOLFSSL_BIO_METHOD *meth;
  /*BIO_ADDR *bio_addr; not supported by wolfSSL */
} coap_dtls_context_t;

typedef struct coap_tls_context_t {
  WOLFSSL_CTX *ctx;
  WOLFSSL_BIO_METHOD *meth;
} coap_tls_context_t;

#define IS_PSK 0x1
#define IS_PKI 0x2

typedef struct sni_entry {
  char *sni;
  WOLFSSL_CTX *ctx;
  coap_dtls_key_t pki_key;
} sni_entry;

typedef struct psk_sni_entry {
  char *sni;
  WOLFSSL_CTX *ctx;
  coap_dtls_spsk_info_t psk_info;
} psk_sni_entry;

typedef struct coap_wolfssl_context_t {
  coap_dtls_context_t dtls;
#if !COAP_DISABLE_TCP
  coap_tls_context_t tls;
#endif /* !COAP_DISABLE_TCP */
  coap_dtls_pki_t setup_data;
  int psk_pki_enabled;
  size_t sni_count;
  sni_entry *sni_entry_list;
  size_t psk_sni_count;
  psk_sni_entry *psk_sni_entry_list;
} coap_wolfssl_context_t;

#if COAP_SERVER_SUPPORT
static int psk_tls_server_name_call_back(WOLFSSL *ssl, int *sd, void *arg);
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_is_supported(void) {
  /* TODO: check for wolfSSL version??*/
  return 1;
}

int
coap_tls_is_supported(void) {
#if !COAP_DISABLE_TCP
  /* TODO: check for wolfSSL version??*/
  return 1;
#else /* COAP_DISABLE_TCP */
  return 0;
#endif /* COAP_DISABLE_TCP */
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_psk_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pki_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_pkcs11_is_supported(void) {
  return 1;
}

/*
 * return 0 failed
 *        1 passed
 */
int
coap_dtls_rpk_is_supported(void) {
  return 0;
}

coap_tls_version_t *
coap_get_tls_library_version(void) {
  static coap_tls_version_t version;
  version.version = wolfSSLeay();
  version.built_version = LIBWOLFSSL_VERSION_HEX;
  version.type = COAP_TLS_LIBRARY_WOLFSSL;

  return &version;
}

void
coap_dtls_startup(void) {
  if (WOLFSSL_DEBUG) {
    wolfSSL_Debugging_ON();
  }
  wolfSSL_load_error_strings();
  wolfSSL_library_init();
}

void
coap_dtls_shutdown(void) {
  wolfSSL_ERR_free_strings();
  coap_dtls_set_log_level(COAP_LOG_EMERG);
}

void *
coap_dtls_get_tls(const coap_session_t *c_session,
                  coap_tls_library_t *tls_lib) {
  if (tls_lib)
    *tls_lib = COAP_TLS_LIBRARY_WOLFSSL;
  if (c_session) {
    return c_session->tls;
  }
  return NULL;
}

/*
 * Logging levels use the standard CoAP logging levels
 */
static coap_log_t dtls_log_level = COAP_LOG_EMERG;

void
coap_dtls_set_log_level(coap_log_t level) {
  dtls_log_level = level;
}

coap_log_t
coap_dtls_get_log_level(void) {
  return dtls_log_level;
}

typedef struct coap_ssl_st {
  coap_session_t *session;
  const void *pdu;
  unsigned pdu_len;
  unsigned peekmode;
  coap_tick_t timeout;
} coap_ssl_data;

static int
coap_dgram_create(WOLFSSL_BIO *a) {
  coap_ssl_data *data = NULL;
  data = malloc(sizeof(coap_ssl_data));
  if (data == NULL)
    return 0;
  //wolfSSL_BIO_set_init(a, 1);
  a->init = 1;  // this reproduces BIO_set_init() behaviour because wolfSSL_BIO_set_init() is a stub
  wolfSSL_BIO_set_data(a, data);
  memset(data, 0x00, sizeof(coap_ssl_data));
  return 1;
}

static int
coap_dgram_destroy(WOLFSSL_BIO *a) {
  coap_ssl_data *data;
  if (a == NULL)
    return 0;
  data = (coap_ssl_data *)wolfSSL_BIO_get_data(a);
  if (data != NULL)
    free(data);
  return 1;
}

static int
coap_dgram_read(WOLFSSL_BIO *a, char *out, int outl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)wolfSSL_BIO_get_data(a);

  if (out != NULL) {
    if (data != NULL && data->pdu_len > 0) {
      if (outl < (int)data->pdu_len) {
        memcpy(out, data->pdu, outl);
        ret = outl;
      } else {
        memcpy(out, data->pdu, data->pdu_len);
        ret = (int)data->pdu_len;
      }
      if (!data->peekmode) {
        data->pdu_len = 0;
        data->pdu = NULL;
      }
    } else {
      ret = -1;
    }
    wolfSSL_BIO_clear_retry_flags(a);
    if (ret < 0)
      wolfSSL_BIO_set_retry_read(a);
  }

  return ret;
}

static int
coap_dgram_write(WOLFSSL_BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_ssl_data *data = (coap_ssl_data *)wolfSSL_BIO_get_data(a);

  if (data->session) {
    if (!coap_netif_available(data->session)
#if COAP_SERVER_SUPPORT
        && data->session->endpoint == NULL
#endif /* COAP_SERVER_SUPPORT */
       ) {
      /* socket was closed on client due to error */
      wolfSSL_BIO_clear_retry_flags(a);
      errno = ECONNRESET;
      return -1;
    }
    ret = (int)data->session->sock.lfunc[COAP_LAYER_TLS].l_write(data->session,
          (const uint8_t *)in,
          inl);
    wolfSSL_BIO_clear_retry_flags(a);
    if (ret <= 0) {
      // Remove brackets after removing debug
      wolfSSL_BIO_set_retry_write(a);
    }
  } else {
    wolfSSL_BIO_clear_retry_flags(a);
    ret = -1;
  }

  return ret;
}

static int
coap_dgram_puts(WOLFSSL_BIO *a, const char *pstr) {
  return coap_dgram_write(a, pstr, (int)strlen(pstr));
}

static long
coap_dgram_ctrl(WOLFSSL_BIO *a, int cmd, long num, void *ptr) {
  long ret = 1;
  /*coap_ssl_data *data = wolfSSL_BIO_get_data(a);*/

  (void)ptr;
  /*TODO: a lot of OpenSSL cases missing */
  switch (cmd) {
  case BIO_CTRL_GET_CLOSE:
    ret = wolfSSL_BIO_get_shutdown(a);
    break;
  case BIO_CTRL_SET_CLOSE:
    wolfSSL_BIO_set_shutdown(a, (int)num);
    ret = 1;
    break;
  case BIO_CTRL_DGRAM_QUERY_MTU:
    ret = -1;
    break;
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    ret = 1;
    break;
  case BIO_CTRL_RESET:
  case BIO_C_FILE_SEEK:
  case BIO_CTRL_INFO:
  case BIO_CTRL_PENDING:
  case BIO_CTRL_WPENDING:
  default:
    ret = 0;
    break;
  }
  return ret;
}

static int
coap_dtls_generate_cookie(WOLFSSL *ssl,
                          unsigned char *cookie,
                          unsigned int *cookie_len) {
  coap_dtls_context_t *dtls =
      (coap_dtls_context_t *)wolfSSL_CTX_get_app_data(wolfSSL_get_SSL_CTX(ssl));
  coap_ssl_data *data = (coap_ssl_data *)wolfSSL_BIO_get_data(wolfSSL_SSL_get_rbio(ssl));
  int r = wolfSSL_HMAC_Init_ex(dtls->cookie_hmac, NULL, 0, NULL, NULL);
  r &= wolfSSL_HMAC_Update(dtls->cookie_hmac,
                           (const uint8_t *)&data->session->addr_info.local.addr,
                           (size_t)data->session->addr_info.local.size);
  r &= wolfSSL_HMAC_Update(dtls->cookie_hmac,
                           (const uint8_t *)&data->session->addr_info.remote.addr,
                           (size_t)data->session->addr_info.remote.size);
  r &= wolfSSL_HMAC_Final(dtls->cookie_hmac, cookie, cookie_len);
  return r;
}

static int
coap_dtls_verify_cookie(WOLFSSL *ssl,
                        const uint8_t *cookie,
                        unsigned int cookie_len) {
  uint8_t hmac[32];
  unsigned len = 32;
  if (coap_dtls_generate_cookie(ssl, hmac, &len) &&
      cookie_len == len && memcmp(cookie, hmac, len) == 0)
    return 1;
  else
    return 0;
}

#if COAP_CLIENT_SUPPORT
static unsigned int
coap_dtls_psk_client_callback(WOLFSSL *ssl,
                              const char *hint,
                              char *identity,
                              unsigned int max_identity_len,
                              unsigned char *psk,
                              unsigned int max_psk_len) {
  coap_session_t *c_session;
  coap_wolfssl_context_t *o_context;
  coap_dtls_cpsk_t *setup_data;
  coap_bin_const_t temp;
  const coap_dtls_cpsk_info_t *cpsk_info;
  const coap_bin_const_t *psk_key;
  const coap_bin_const_t *psk_identity;

  c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  if (c_session == NULL)
    return 0;
  o_context = (coap_wolfssl_context_t *)c_session->context->dtls_context;
  if (o_context == NULL)
    return 0;
  setup_data = &c_session->cpsk_setup_data;

  temp.s = hint ? (const uint8_t *)hint : (const uint8_t *)"";
  temp.length = strlen((const char *)temp.s);
  coap_session_refresh_psk_hint(c_session, &temp);

  coap_log_debug("got psk_identity_hint: '%.*s'\n", (int)temp.length,
                 (const char *)temp.s);

  if (setup_data->validate_ih_call_back) {
    coap_str_const_t lhint;

    lhint.s = temp.s;
    lhint.length = temp.length;
    cpsk_info =
        setup_data->validate_ih_call_back(&lhint,
                                          c_session,
                                          setup_data->ih_call_back_arg);

    if (cpsk_info == NULL)
      return 0;

    coap_session_refresh_psk_identity(c_session, &cpsk_info->identity);
    coap_session_refresh_psk_key(c_session, &cpsk_info->key);
    psk_identity = &cpsk_info->identity;
    psk_key = &cpsk_info->key;
  } else {
    psk_identity = coap_get_session_client_psk_identity(c_session);
    psk_key = coap_get_session_client_psk_key(c_session);
  }

  if (psk_identity == NULL || psk_key == NULL) {
    coap_log_warn("no PSK available\n");
    return 0;
  }

  /* identity has to be NULL terminated */
  if (!max_identity_len)
    return 0;
  max_identity_len--;
  if (psk_identity->length > max_identity_len) {
    coap_log_warn("psk_identity too large, truncated to %d bytes\n",
                  max_identity_len);
  } else {
    /* Reduce to match */
    max_identity_len = (unsigned int)psk_identity->length;
  }
  memcpy(identity, psk_identity->s, max_identity_len);
  identity[max_identity_len] = '\000';

  if (psk_key->length > max_psk_len) {
    coap_log_warn("psk_key too large, truncated to %d bytes\n",
                  max_psk_len);
  } else {
    /* Reduce to match */
    max_psk_len = (unsigned int)psk_key->length;
  }
  memcpy(psk, psk_key->s, max_psk_len);
  return max_psk_len;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
static unsigned int
coap_dtls_psk_server_callback(
    WOLFSSL *ssl,
    const char *identity,
    unsigned char *psk,
    unsigned int max_psk_len
) {
  coap_session_t *c_session;
  coap_dtls_spsk_t *setup_data;
  coap_bin_const_t lidentity;
  const coap_bin_const_t *psk_key;

  c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  if (c_session == NULL)
    return 0;

  setup_data = &c_session->context->spsk_setup_data;

  /* Track the Identity being used */
  lidentity.s = identity ? (const uint8_t *)identity : (const uint8_t *)"";
  lidentity.length = strlen((const char *)lidentity.s);
  coap_session_refresh_psk_identity(c_session, &lidentity);

  coap_log_debug("got psk_identity: '%.*s'\n",
                 (int)lidentity.length, (const char *)lidentity.s);

  if (setup_data->validate_id_call_back) {
    psk_key = setup_data->validate_id_call_back(&lidentity,
                                                c_session,
                                                setup_data->id_call_back_arg);

    coap_session_refresh_psk_key(c_session, psk_key);
  } else {
    psk_key = coap_get_session_server_psk_key(c_session);
  }

  if (psk_key == NULL)
    return 0;

  if (psk_key->length > max_psk_len) {
    coap_log_warn("psk_key too large, truncated to %d bytes\n",
                  max_psk_len);
  } else {
    /* Reduce to match */
    max_psk_len = (unsigned int)psk_key->length;
  }
  memcpy(psk, psk_key->s, max_psk_len);
  return max_psk_len;
}
#endif /* COAP_SERVER_SUPPORT */

static const char *
ssl_function_definition(unsigned long e) {
  static char buff[80];

  snprintf(buff, sizeof(buff), " at %s:%s",
           wolfSSL_ERR_lib_error_string(e), wolfSSL_ERR_func_error_string(e));
  return buff;
}

static void
coap_dtls_info_callback(const WOLFSSL *ssl, int where, int ret) {
  coap_session_t *session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  const char *pstr;
  int w = where &~SSL_ST_MASK;

  if (w & SSL_ST_CONNECT)
    pstr = "wolfSSL_connect";
  else if (w & SSL_ST_ACCEPT)
    pstr = "wolfSSL_accept";
  else
    pstr = "undefined";

  if (where & SSL_CB_LOOP) {
    coap_dtls_log(COAP_LOG_DEBUG, "*  %s: %s:%s\n",
                  coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
  } else if (where & SSL_CB_ALERT) {
    coap_log_t log_level = COAP_LOG_INFO;
    pstr = (where & SSL_CB_READ) ? "read" : "write";
    if ((where & (SSL_CB_WRITE|SSL_CB_READ)) && (ret >> 8) == WOLFSSL3_AL_FATAL) {
      session->dtls_event = COAP_EVENT_DTLS_ERROR;
      if ((ret & 0xff) != close_notify)
        log_level = COAP_LOG_WARN;
    }

    /* Need to let CoAP logging know why this session is dying */
    coap_log(log_level, "*  %s: SSL3 alert %s:%s:%s\n",
             coap_session_str(session),
             pstr,
             wolfSSL_alert_type_string_long(ret),
             wolfSSL_alert_desc_string_long(ret));
  } else if (where & SSL_CB_EXIT) {
    if (ret == 0) {
      if (dtls_log_level >= COAP_LOG_WARN) {
        unsigned long e;
        coap_dtls_log(COAP_LOG_WARN, "*  %s: %s:failed in %s\n",
                      coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
        while ((e = wolfSSL_ERR_get_error()))
          coap_dtls_log(COAP_LOG_WARN, "*  %s: %s%s\n",
                        coap_session_str(session), wolfSSL_ERR_reason_error_string(e),
                        ssl_function_definition(e));
      }
    } else if (ret < 0) {
      if (dtls_log_level >= COAP_LOG_WARN) {
        int err = wolfSSL_get_error((WOLFSSL *)ssl, ret);
        if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE &&
            err != WOLFSSL_ERROR_WANT_CONNECT && err != WOLFSSL_ERROR_WANT_ACCEPT &&
            err != WOLFSSL_ERROR_WANT_X509_LOOKUP) {
          long e;
          coap_dtls_log(COAP_LOG_WARN, "*  %s: %s:error in %s\n",
                        coap_session_str(session), pstr, wolfSSL_state_string_long(ssl));
          while ((e = wolfSSL_ERR_get_error()))
            coap_dtls_log(COAP_LOG_WARN, "*  %s: %s%s\n",
                          coap_session_str(session), wolfSSL_ERR_reason_error_string(e),
                          ssl_function_definition(e));
        }
      }
    }
  }

  if (where == SSL_CB_HANDSHAKE_START &&
      wolfSSL_is_init_finished((WOLFSSL *)ssl))
    /* instead of SSL_get_state SSL_get_state(ssl) == TLS_ST_OK*/
    session->dtls_event = COAP_EVENT_DTLS_RENEGOTIATE;
}

#if !COAP_DISABLE_TCP
static int
coap_sock_create(WOLFSSL_BIO *a) {
  //wolfSSL_BIO_set_init(a, 1);
  a->init = 1;  // this reproduces BIO_set_init() behaviour because wolfSSL_BIO_set_init() is a stub
  return 1;
}

static int
coap_sock_destroy(WOLFSSL_BIO *a) {
  (void)a;
  return 1;
}

/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -1  error
 */
static int
coap_sock_read(WOLFSSL_BIO *a, char *out, int outl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)wolfSSL_BIO_get_data(a);

  if (out != NULL) {
    ret =(int)session->sock.lfunc[COAP_LAYER_TLS].l_read(session, (u_char *)out,
                                                         outl);
    if (ret == 0) {
      wolfSSL_BIO_set_retry_read(a);
      ret = -1;
    } else {
      wolfSSL_BIO_clear_retry_flags(a);
    }
  }
  return ret;
}

/*
 * strm
 * return +ve data amount
 *        0   no more
 *        -1  error (error in errno)
 */
static int
coap_sock_write(WOLFSSL_BIO *a, const char *in, int inl) {
  int ret = 0;
  coap_session_t *session = (coap_session_t *)wolfSSL_BIO_get_data(a);

  ret = (int)session->sock.lfunc[COAP_LAYER_TLS].l_write(session,
                                                         (const uint8_t *)in,
                                                         inl);
  /* Translate layer what returns into what wolfSSL expects */
  wolfSSL_BIO_clear_retry_flags(a);
  if (ret == 0) {
    wolfSSL_BIO_set_retry_read(a);
    ret = -1;
  } else {
    wolfSSL_BIO_clear_retry_flags(a);
    if (ret == -1) {
      if ((session->state == COAP_SESSION_STATE_CSM ||
           session->state == COAP_SESSION_STATE_HANDSHAKE) &&
          (errno == EPIPE || errno == ECONNRESET)) {
        /*
         * Need to handle a TCP timing window where an agent continues with
         * the sending of the next handshake or a CSM.
         * However, the peer does not like a certificate and so sends a
         * fatal alert and closes the TCP session.
         * The sending of the next handshake or CSM may get terminated because
         * of the closed TCP session, but there is still an outstanding alert
         * to be read in and reported on.
         * In this case, pretend that sending the info was fine so that the
         * alert can be read (which effectively is what happens with DTLS).
         */
        ret = inl;
      }
    }
  }
  return ret;
}

static int
coap_sock_puts(WOLFSSL_BIO *a, const char *pstr) {
  return coap_sock_write(a, pstr, (int)strlen(pstr));
}

static long
coap_sock_ctrl(WOLFSSL_BIO *a, int cmd, long num, void *ptr) {
  int r = 1;
  (void)a;
  (void)ptr;
  (void)num;
  switch (cmd) {
  /* cases BIO_C_SET_FD and BIO_C_GET_FD missing*/
  case BIO_CTRL_SET_CLOSE:
  case BIO_CTRL_DUP:
  case BIO_CTRL_FLUSH:
    r = 1;
    break;
  default:
  case BIO_CTRL_GET_CLOSE:
    r = 0;
    break;
  }
  return r;
}
#endif /* !COAP_DISABLE_TCP */

static void
coap_set_user_prefs(WOLFSSL_CTX *ctx) {
  wolfSSL_CTX_set_cipher_list(ctx, COAP_WOLFSSL_CIPHERS);

#ifdef COAP_WOLFSSL_SIGALGS
  wolfSSL_CTX_set1_sigalgs_list(ctx, COAP_WOLFSSL_SIGALGS);
#endif
#ifdef COAP_WOLFSSL_GROUPS
  int ret;
  ret = wolfSSL_CTX_set1_groups_list(ctx,
                                     (char *) COAP_WOLFSSL_GROUPS);
  if (ret != WOLFSSL_SUCCESS) {
    coap_log_debug("Failed to set group list\n");
  }
#endif
}

void *
coap_dtls_new_context(coap_context_t *coap_context) {
  coap_wolfssl_context_t *context;
  (void)coap_context;

  context = (coap_wolfssl_context_t *)coap_malloc_type(COAP_STRING, sizeof(coap_wolfssl_context_t));
  if (context) {
    uint8_t cookie_secret[32];

    memset(context, 0, sizeof(coap_wolfssl_context_t));

    /* Set up DTLS context */
    context->dtls.ctx = wolfSSL_CTX_new(wolfDTLS_method());
    if (!context->dtls.ctx)
      goto error;
    wolfSSL_CTX_set_min_proto_version(context->dtls.ctx,
                                      DTLS1_2_VERSION);
    wolfSSL_CTX_set_app_data(context->dtls.ctx, &context->dtls);
    wolfSSL_CTX_set_read_ahead(context->dtls.ctx, 1);
    coap_set_user_prefs(context->dtls.ctx);
    memset(cookie_secret, 0, sizeof(cookie_secret));
    if (!wolfSSL_RAND_bytes(cookie_secret, (int)sizeof(cookie_secret))) {
      coap_dtls_log(COAP_LOG_WARN,
                    "Insufficient entropy for random cookie generation");
      coap_prng(cookie_secret, sizeof(cookie_secret));
    }
    context->dtls.cookie_hmac = wolfSSL_HMAC_CTX_new();
    if (!wolfSSL_HMAC_Init_ex(context->dtls.cookie_hmac, cookie_secret, (int)sizeof(cookie_secret),
                              wolfSSL_EVP_sha256(), NULL))
      goto error;

    wolfSSL_CTX_set_info_callback(context->dtls.ctx, coap_dtls_info_callback);
    wolfSSL_CTX_set_options(context->dtls.ctx, WOLFSSL_OP_NO_QUERY_MTU);
    /*BIO_TYPE_DGRAM not available*/
    context->dtls.meth = wolfSSL_BIO_meth_new(COAP_BIO_TYPE_DGRAM,
                                              "coapdgram");
    if (!context->dtls.meth)
      goto error;

    wolfSSL_BIO_meth_set_write(context->dtls.meth, coap_dgram_write);
    wolfSSL_BIO_meth_set_read(context->dtls.meth, coap_dgram_read);
    wolfSSL_BIO_meth_set_puts(context->dtls.meth, coap_dgram_puts);
    wolfSSL_BIO_meth_set_ctrl(context->dtls.meth, coap_dgram_ctrl);
    wolfSSL_BIO_meth_set_create(context->dtls.meth, coap_dgram_create);
    wolfSSL_BIO_meth_set_destroy(context->dtls.meth, coap_dgram_destroy);

#if !COAP_DISABLE_TCP
    /* Set up TLS context */
    context->tls.ctx = wolfSSL_CTX_new(wolfSSLv23_method());
    if (!context->tls.ctx)
      goto error;
    wolfSSL_CTX_set_app_data(context->tls.ctx, &context->tls);
    wolfSSL_CTX_set_min_proto_version(context->tls.ctx, TLS1_VERSION);
    coap_set_user_prefs(context->tls.ctx);
    wolfSSL_CTX_set_info_callback(context->tls.ctx, coap_dtls_info_callback);
    /*BIO_TYPE_SOCKET not available*/
    context->tls.meth = wolfSSL_BIO_meth_new(COAP_BIO_TYPE_SOCKET,
                                             "coapsock");
    if (!context->tls.meth)
      goto error;
    wolfSSL_BIO_meth_set_write(context->tls.meth, coap_sock_write);
    wolfSSL_BIO_meth_set_read(context->tls.meth, coap_sock_read);
    wolfSSL_BIO_meth_set_puts(context->tls.meth, coap_sock_puts);
    wolfSSL_BIO_meth_set_ctrl(context->tls.meth, coap_sock_ctrl);
    wolfSSL_BIO_meth_set_create(context->tls.meth, coap_sock_create);
    wolfSSL_BIO_meth_set_destroy(context->tls.meth, coap_sock_destroy);
#endif /* !COAP_DISABLE_TCP */
  }

  return context;

error:
  coap_dtls_free_context(context);
  return NULL;
}

#if COAP_SERVER_SUPPORT
int
coap_dtls_context_set_spsk(coap_context_t *c_context,
                           coap_dtls_spsk_t *setup_data
                          ) {
  coap_wolfssl_context_t *o_context =
      ((coap_wolfssl_context_t *)c_context->dtls_context);
  WOLFSSL_BIO *bio;

  if (!setup_data || !o_context)
    return 0;

  wolfSSL_CTX_set_psk_server_callback(o_context->dtls.ctx,
                                      coap_dtls_psk_server_callback);

#if !COAP_DISABLE_TCP
  wolfSSL_CTX_set_psk_server_callback(o_context->tls.ctx,
                                      coap_dtls_psk_server_callback);
#endif /* !COAP_DISABLE_TCP */
  if (setup_data->psk_info.hint.s) {
    char hint[COAP_DTLS_HINT_LENGTH];
    snprintf(hint, sizeof(hint), "%.*s", (int)setup_data->psk_info.hint.length,
             setup_data->psk_info.hint.s);
    wolfSSL_CTX_use_psk_identity_hint(o_context->dtls.ctx, hint);
#if !COAP_DISABLE_TCP
    wolfSSL_CTX_use_psk_identity_hint(o_context->tls.ctx, hint);
#endif /* !COAP_DISABLE_TCP */
  }
  if (setup_data->validate_sni_call_back) {
    wolfSSL_CTX_set_servername_arg(o_context->dtls.ctx,
                                   &c_context->spsk_setup_data);
    wolfSSL_CTX_set_tlsext_servername_callback(o_context->dtls.ctx,
                                               psk_tls_server_name_call_back);
#if !COAP_DISABLE_TCP
    wolfSSL_CTX_set_servername_arg(o_context->tls.ctx,
                                   &c_context->spsk_setup_data);
    wolfSSL_CTX_set_tlsext_servername_callback(o_context->tls.ctx,
                                               psk_tls_server_name_call_back);
#endif /* !COAP_DISABLE_TCP */
  }
  if (!o_context->dtls.ssl) {
    /* This is set up to handle new incoming sessions to a server */
    o_context->dtls.ssl = wolfSSL_new(o_context->dtls.ctx);
    if (!o_context->dtls.ssl)
      return 0;
    bio = wolfSSL_BIO_new(o_context->dtls.meth);
    if (!bio) {
      wolfSSL_free(o_context->dtls.ssl);
      o_context->dtls.ssl = NULL;
      return 0;
    }
    wolfSSL_set_bio(o_context->dtls.ssl, bio, bio);
    wolfSSL_set_app_data(o_context->dtls.ssl, NULL);
    wolfSSL_set_options(o_context->dtls.ssl, WOLFSSL_OP_COOKIE_EXCHANGE);
    wolfSSL_dtls_set_mtu(o_context->dtls.ssl,
                         COAP_DEFAULT_MTU);
  }
  o_context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
int
coap_dtls_context_set_cpsk(coap_context_t *c_context,
                           coap_dtls_cpsk_t *setup_data
                          ) {
  coap_wolfssl_context_t *o_context =
      ((coap_wolfssl_context_t *)c_context->dtls_context);
  WOLFSSL_BIO *bio;

  if (!setup_data || !o_context)
    return 0;

  if (!o_context->dtls.ssl) {
    /* This is set up to handle new incoming sessions to a server */
    o_context->dtls.ssl = wolfSSL_new(o_context->dtls.ctx);
    if (!o_context->dtls.ssl)
      return 0;
    bio = wolfSSL_BIO_new(o_context->dtls.meth);
    if (!bio) {
      wolfSSL_free(o_context->dtls.ssl);
      o_context->dtls.ssl = NULL;
      return 0;
    }
    wolfSSL_set_bio(o_context->dtls.ssl, bio, bio);
    wolfSSL_set_app_data(o_context->dtls.ssl, NULL);
    wolfSSL_set_options(o_context->dtls.ssl, WOLFSSL_OP_COOKIE_EXCHANGE);
    wolfSSL_dtls_set_mtu(o_context->dtls.ssl,
                         COAP_DEFAULT_MTU);
  }
  o_context->psk_pki_enabled |= IS_PSK;
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

/*
Note: The returned key type is not actually used in wolfSSL_use_PrivateKey_ASN1.
The key type is inferred internally by wolfSSL when using wolfSSL_use_PrivateKey_buffer.
*/
static int
map_key_type(int asn1_private_key_type
            ) {
  /* some OpenSSL EVP_PKEYs not available in compatibility layer:
  COAP_ASN1_PKEY_RSA2, COAP_ASN1_PKEY_DSA[1-4], COAP_ASN1_PKEY_DHX
  and COAP_ASN1_PKEY_TLS1_PRF */
  switch (asn1_private_key_type) {
  case COAP_ASN1_PKEY_NONE:
    return EVP_PKEY_NONE;
  case COAP_ASN1_PKEY_RSA:
    return EVP_PKEY_RSA;
  case COAP_ASN1_PKEY_RSA2:
    return EVP_PKEY_RSA;
  case COAP_ASN1_PKEY_DSA:
    return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DSA1:
    return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DSA2:
    return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DSA3:
    return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DSA4:
    return EVP_PKEY_DSA;
  case COAP_ASN1_PKEY_DH:
    return EVP_PKEY_DH;
  case COAP_ASN1_PKEY_DHX:
    return EVP_PKEY_DH;
  case COAP_ASN1_PKEY_EC:
    return EVP_PKEY_EC;
  case COAP_ASN1_PKEY_HMAC:
    return EVP_PKEY_HMAC;
  case COAP_ASN1_PKEY_CMAC:
    return EVP_PKEY_CMAC;
  case COAP_ASN1_PKEY_TLS1_PRF:
    return EVP_PKEY_HKDF;
  case COAP_ASN1_PKEY_HKDF:
    return EVP_PKEY_HKDF;
  default:
    coap_log_warn("*** setup_pki: DTLS: Unknown Private Key type %d for ASN1\n",
                  asn1_private_key_type);
    break;
  }
  return 0;
}
#if !COAP_DISABLE_TCP
static uint8_t coap_alpn[] = { 4, 'c', 'o', 'a', 'p' };

#if COAP_SERVER_SUPPORT
static int
server_alpn_callback(WOLFSSL *ssl COAP_UNUSED,
                     const unsigned char **out,
                     unsigned char *outlen,
                     const unsigned char *in,
                     unsigned int inlen,
                     void *arg COAP_UNUSED
                    ) {
  unsigned char *tout = NULL;
  int ret;
  if (inlen == 0)
    return SSL_TLSEXT_ERR_NOACK;
  ret = wolfSSL_select_next_proto(&tout,
                                  outlen,
                                  coap_alpn,
                                  sizeof(coap_alpn),
                                  in,
                                  inlen);
  *out = tout;
  return (ret != OPENSSL_NPN_NEGOTIATED) ? noack_return : WOLFSSL_TLSEXT_ERR_OK;
}
#endif /* COAP_SERVER_SUPPORT */
#endif /* !COAP_DISABLE_TCP */

static void
add_ca_to_cert_store(WOLFSSL_X509_STORE *st, WOLFSSL_X509 *x509) {
  long e;

  /* Flush out existing errors */
  while ((e = wolfSSL_ERR_get_error()) != 0) {
  }

  if (!wolfSSL_X509_STORE_add_cert(st, x509)) {
    while ((e = wolfSSL_ERR_get_error()) != 0) {
      int r = wolfSSL_ERR_GET_REASON(e);
      if (r != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        /* Not already added */
        coap_log_warn("***setup_pki: (D)TLS: %s%s\n",
                      wolfSSL_ERR_reason_error_string(e),
                      ssl_function_definition(e));
      }
    }
  }
}

static int
setup_pki_server(SSL_CTX *ctx,
                 const coap_dtls_pki_t *setup_data
                ) {
  switch (setup_data->pki_key.key_type) {
  case COAP_PKI_KEY_PEM:
    if (setup_data->pki_key.key.pem.public_cert &&
        setup_data->pki_key.key.pem.public_cert[0]) {
      if (!(wolfSSL_CTX_use_certificate_file(ctx,
                                             setup_data->pki_key.key.pem.public_cert,
                                             WOLFSSL_FILETYPE_PEM))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "Server Certificate\n",
                      setup_data->pki_key.key.pem.public_cert);
        return 0;
      }
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem.private_key &&
        setup_data->pki_key.key.pem.private_key[0]) {
      if (!(wolfSSL_CTX_use_PrivateKey_file(ctx,
                                            setup_data->pki_key.key.pem.private_key,
                                            WOLFSSL_FILETYPE_PEM))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "Server Private Key\n",
                      setup_data->pki_key.key.pem.private_key);
        return 0;
      }
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->check_common_ca && setup_data->pki_key.key.pem.ca_file &&
        setup_data->pki_key.key.pem.ca_file[0]) {
      WOLF_STACK_OF(WOLFSSL_X509_NAME) *cert_names;
      WOLFSSL_X509_STORE *st;
      WOLFSSL_BIO *in;
      WOLFSSL_X509 *x = NULL;
      char *rw_var = NULL;
      cert_names = wolfSSL_load_client_CA_file(setup_data->pki_key.key.pem.ca_file);
      if (cert_names != NULL) {
        wolfSSL_CTX_set_client_CA_list(ctx, cert_names);
      } else {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "client CA File\n",
                      setup_data->pki_key.key.pem.ca_file);
        return 0;
      }

      /* Add CA to the trusted root CA store */
      st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));
      in = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
      /* Need to do this to not get a compiler warning about const parameters */
      memcpy(&rw_var, &setup_data->pki_key.key.pem.ca_file, sizeof(rw_var));
      if (!wolfSSL_BIO_read_filename(in, rw_var)) {
        wolfSSL_BIO_free(in);
        wolfSSL_X509_free(x);
        break;
      }

      for (;;) {
        if ((x = wolfSSL_PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
          break;
        add_ca_to_cert_store(st, x);
        wolfSSL_X509_free(x);
      }
      wolfSSL_BIO_free(in);
    }
    break;

  case COAP_PKI_KEY_PEM_BUF:
    if (setup_data->pki_key.key.pem_buf.public_cert &&
        setup_data->pki_key.key.pem_buf.public_cert_len) {
      WOLFSSL_BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.public_cert,
                                                setup_data->pki_key.key.pem_buf.public_cert_len);
      WOLFSSL_X509 *cert = bp ? wolfSSL_PEM_read_bio_X509(bp, NULL, 0, NULL) : NULL;

      if (!cert || !wolfSSL_CTX_use_certificate(ctx, cert)) {
        coap_log_warn("*** setup_pki: (D)TLS: Unable to configure "
                      "Server PEM Certificate\n");
        if (bp)
          wolfSSL_BIO_free(bp);
        if (cert)
          wolfSSL_X509_free(cert);
        return 0;
      }
      if (bp)
        wolfSSL_BIO_free(bp);
      if (cert)
        wolfSSL_X509_free(cert);
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem_buf.private_key &&
        setup_data->pki_key.key.pem_buf.private_key_len) {
      BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.private_key,
                                        setup_data->pki_key.key.pem_buf.private_key_len);
      EVP_PKEY *pkey = bp ? wolfSSL_PEM_read_bio_PrivateKey(bp, NULL, 0, NULL) : NULL;

      if (!pkey || !wolfSSL_CTX_use_PrivateKey(ctx, pkey)) {
        coap_log_warn("*** setup_pki: (D)TLS: Unable to configure "
                      "Server PEM Private Key\n");
        if (bp)
          wolfSSL_BIO_free(bp);
        if (pkey)
          wolfSSL_EVP_PKEY_free(pkey);
        return 0;
      }
      if (bp)
        wolfSSL_BIO_free(bp);
      if (pkey)
        wolfSSL_EVP_PKEY_free(pkey);
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem_buf.ca_cert &&
        setup_data->pki_key.key.pem_buf.ca_cert_len) {
      BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.ca_cert,
                                        setup_data->pki_key.key.pem_buf.ca_cert_len);
      X509_STORE *st;
      X509 *x;

      st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));
      if (bp) {
        for (;;) {
          if ((x = wolfSSL_PEM_read_bio_X509(bp, NULL, NULL, NULL)) == NULL)
            break;
          add_ca_to_cert_store(st, x);
          wolfSSL_CTX_add_client_CA(ctx, x);
          wolfSSL_X509_free(x);
        }
        wolfSSL_BIO_free(bp);
      }
    }
    break;

  case COAP_PKI_KEY_ASN1:
    if (setup_data->pki_key.key.asn1.public_cert &&
        setup_data->pki_key.key.asn1.public_cert_len > 0) {
      if (!(wolfSSL_CTX_use_certificate_ASN1(ctx,
                                             setup_data->pki_key.key.asn1.public_cert_len,
                                             setup_data->pki_key.key.asn1.public_cert))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "Server Certificate\n",
                      "ASN1");
        return 0;
      }
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.asn1.private_key &&
        setup_data->pki_key.key.asn1.private_key_len > 0) {
      int pkey_type = map_key_type(setup_data->pki_key.key.asn1.private_key_type);
      /*wolfSSL_CTX_use_PrivateKey_ASN1 expects a unsigned char* unlike OpenSSL equivalent */
      unsigned char *asn1_pkey_buffer = malloc(setup_data->pki_key.key.asn1.private_key_len);
      if (asn1_pkey_buffer) {
        memcpy(asn1_pkey_buffer, setup_data->pki_key.key.asn1.private_key,
               setup_data->pki_key.key.asn1.private_key_len);

        if (!wolfSSL_CTX_use_PrivateKey_ASN1(pkey_type, ctx, asn1_pkey_buffer,
                                             setup_data->pki_key.key.asn1.private_key_len)) {
          coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure Server Private Key\n", "ASN1");
          free(asn1_pkey_buffer);
          return 0;
        }
        free(asn1_pkey_buffer);
      }
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.asn1.ca_cert &&
        setup_data->pki_key.key.asn1.ca_cert_len > 0) {
      /* Need to use a temp variable as it gets incremented*/
      const uint8_t *p = setup_data->pki_key.key.asn1.ca_cert;
      WOLFSSL_X509 *x509 = wolfSSL_d2i_X509(NULL, &p, setup_data->pki_key.key.asn1.ca_cert_len);
      WOLFSSL_X509_STORE *st;
      if (!x509 || !wolfSSL_CTX_add_client_CA(ctx, x509)) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "client CA File\n",
                      "ASN1");
        if (x509)
          X509_free(x509);
        return 0;
      }
      st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));
      add_ca_to_cert_store(st, x509);
      X509_free(x509);
    }
    break;

  case COAP_PKI_KEY_PKCS11:
    /* //TODO: check if this case can be implemented */
    coap_log_err("*** setup_pki: (D)TLS: PKCS11 not supported\n");
    return 0;

  default:
    coap_log_err("*** setup_pki: (D)TLS: Unknown key type %d\n",
                 setup_data->pki_key.key_type);
    return 0;
  }

  return 1;
}

#if COAP_CLIENT_SUPPORT
static int
setup_pki_ssl(WOLFSSL *ssl,
              coap_dtls_pki_t *setup_data, coap_dtls_role_t role
             ) {
  if (setup_data->is_rpk_not_cert) {
    coap_log_err("RPK Support not available in wolfSSL\n");
    return 0;
  }
  switch (setup_data->pki_key.key_type) {
  case COAP_PKI_KEY_PEM:
    if (setup_data->pki_key.key.pem.public_cert &&
        setup_data->pki_key.key.pem.public_cert[0]) {
      if (!(wolfSSL_use_certificate_file(ssl,
                                         setup_data->pki_key.key.pem.public_cert,
                                         WOLFSSL_FILETYPE_PEM))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "%s Certificate\n",
                      setup_data->pki_key.key.pem.public_cert,
                      role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
        return 0;
      }
    } else if (role == COAP_DTLS_ROLE_SERVER ||
               (setup_data->pki_key.key.pem.private_key &&
                setup_data->pki_key.key.pem.private_key[0])) {
      coap_log_err("*** setup_pki: (D)TLS: No %s Certificate defined\n",
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.pem.private_key &&
        setup_data->pki_key.key.pem.private_key[0]) {
      if (!(wolfSSL_use_PrivateKey_file(ssl,
                                        setup_data->pki_key.key.pem.private_key,
                                        WOLFSSL_FILETYPE_PEM))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "Client Private Key\n",
                      setup_data->pki_key.key.pem.private_key);
        return 0;
      }
    } else if (role == COAP_DTLS_ROLE_SERVER ||
               (setup_data->pki_key.key.pem.public_cert &&
                setup_data->pki_key.key.pem.public_cert[0])) {
      coap_log_err("*** setup_pki: (D)TLS: No %s Private Key defined\n",
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->check_common_ca && setup_data->pki_key.key.pem.ca_file &&
        setup_data->pki_key.key.pem.ca_file[0]) {
      WOLFSSL_X509_STORE *st;
      WOLFSSL_BIO *in;
      WOLFSSL_X509 *x = NULL;
      char *rw_var = NULL;
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);

      if (role == COAP_DTLS_ROLE_SERVER) {
        WOLF_STACK_OF(WOLFSSL_X509_NAME) *cert_names = wolfSSL_load_client_CA_file(
                                                           setup_data->pki_key.key.pem.ca_file);

        if (cert_names != NULL)
          wolfSSL_set_client_CA_list(ssl, cert_names);
        else {
          coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                        "%s CA File\n",
                        setup_data->pki_key.key.pem.ca_file,
                        role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
          return 0;
        }
      }

      /* Add CA to the trusted root CA store */
      in = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
      /* Need to do this to not get a compiler warning about const parameters */
      memcpy(&rw_var, &setup_data->pki_key.key.pem.ca_file, sizeof(rw_var));
      if (!wolfSSL_BIO_read_filename(in, rw_var)) {
        wolfSSL_BIO_free(in);
        break;
      }
      st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));
      for (;;) {
        if ((x = wolfSSL_PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
          break;
        add_ca_to_cert_store(st, x);
        wolfSSL_X509_free(x);
      }
      wolfSSL_BIO_free(in);
    }
    break;

  case COAP_PKI_KEY_PEM_BUF:
    if (setup_data->pki_key.key.pem_buf.public_cert &&
        setup_data->pki_key.key.pem_buf.public_cert_len) {
      WOLFSSL_BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.public_cert,
                                                (int)setup_data->pki_key.key.pem_buf.public_cert_len);
      WOLFSSL_X509 *cert = bp ? wolfSSL_PEM_read_bio_X509(bp, NULL, 0, NULL) : NULL;

      if (!cert || !SSL_use_certificate(ssl, cert)) {
        coap_log_warn("*** setup_pki: (D)TLS: Unable to configure "
                      "Server PEM Certificate\n");
        if (bp)
          wolfSSL_BIO_free(bp);
        if (cert)
          wolfSSL_X509_free(cert);
        return 0;
      }
      if (bp)
        wolfSSL_BIO_free(bp);
      if (cert)
        wolfSSL_X509_free(cert);
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Certificate defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem_buf.private_key &&
        setup_data->pki_key.key.pem_buf.private_key_len) {
      WOLFSSL_BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.private_key,
                                                (int)setup_data->pki_key.key.pem_buf.private_key_len);
      WOLFSSL_EVP_PKEY *pkey = bp ? wolfSSL_PEM_read_bio_PrivateKey(bp, NULL, 0, NULL) : NULL;

      if (!pkey || !SSL_use_PrivateKey(ssl, pkey)) {
        coap_log_warn("*** setup_pki: (D)TLS: Unable to configure "
                      "Server PEM Private Key\n");
        if (bp)
          wolfSSL_BIO_free(bp);
        if (pkey)
          wolfSSL_EVP_PKEY_free(pkey);
        return 0;
      }
      if (bp)
        wolfSSL_BIO_free(bp);
      if (pkey)
        wolfSSL_EVP_PKEY_free(pkey);
    } else {
      coap_log_err("*** setup_pki: (D)TLS: No Server Private Key defined\n");
      return 0;
    }

    if (setup_data->pki_key.key.pem_buf.ca_cert &&
        setup_data->pki_key.key.pem_buf.ca_cert_len) {
      WOLFSSL_BIO *bp = wolfSSL_BIO_new_mem_buf(setup_data->pki_key.key.pem_buf.ca_cert,
                                                (int)setup_data->pki_key.key.pem_buf.ca_cert_len);
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);
      WOLFSSL_X509 *x;
      WOLFSSL_X509_STORE *st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));

      if (bp) {
        for (;;) {
          if ((x = wolfSSL_PEM_read_bio_X509(bp, NULL, 0, NULL)) == NULL)
            break;
          add_ca_to_cert_store(st, x);
          wolfSSL_CTX_add_client_CA(ctx, x);
          wolfSSL_X509_free(x);
        }
        wolfSSL_BIO_free(bp);
      }
    }
    break;

  case COAP_PKI_KEY_ASN1:
    if (setup_data->pki_key.key.asn1.public_cert &&
        setup_data->pki_key.key.asn1.public_cert_len > 0) {
      if (!(wolfSSL_use_certificate_ASN1(ssl,
                                         setup_data->pki_key.key.asn1.public_cert,
                                         (int)setup_data->pki_key.key.asn1.public_cert_len))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "%s Certificate\n",
                      role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client",
                      "ASN1");
        return 0;
      }
    } else if (role == COAP_DTLS_ROLE_SERVER ||
               (setup_data->pki_key.key.asn1.private_key &&
                setup_data->pki_key.key.asn1.private_key[0])) {
      coap_log_err("*** setup_pki: (D)TLS: No %s Certificate defined\n",
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.asn1.private_key &&
        setup_data->pki_key.key.asn1.private_key_len > 0) {
      int pkey_type = map_key_type(setup_data->pki_key.key.asn1.private_key_type);
      if (!(wolfSSL_use_PrivateKey_ASN1(pkey_type, ssl,
                                        setup_data->pki_key.key.asn1.private_key,
                                        (long)setup_data->pki_key.key.asn1.private_key_len))) {
        coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                      "%s Private Key\n",
                      role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client",
                      "ASN1");
        return 0;
      }
    } else if (role == COAP_DTLS_ROLE_SERVER ||
               (setup_data->pki_key.key.asn1.public_cert &&
                setup_data->pki_key.key.asn1.public_cert_len > 0)) {
      coap_log_err("*** setup_pki: (D)TLS: No %s Private Key defined",
                   role == COAP_DTLS_ROLE_SERVER ? "Server" : "Client");
      return 0;
    }
    if (setup_data->pki_key.key.asn1.ca_cert &&
        setup_data->pki_key.key.asn1.ca_cert_len > 0) {
      /* Need to use a temp variable as it gets incremented*/
      const uint8_t *p = setup_data->pki_key.key.asn1.ca_cert;
      WOLFSSL_X509 *x509 = wolfSSL_d2i_X509(NULL, &p, (long)setup_data->pki_key.key.asn1.ca_cert_len);
      WOLFSSL_X509_STORE *st;
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);

      if (role == COAP_DTLS_ROLE_SERVER) {
        if (!x509 ||
            !wolfSSL_CTX_add_client_CA(ctx,
                                       x509)) {
          coap_log_warn("*** setup_pki: (D)TLS: %s: Unable to configure "
                        "client CA File\n",
                        "ASN1");
          wolfSSL_X509_free(x509);
          return 0;
        }
      }

      /* Add CA to the trusted root CA store */
      st = wolfSSL_CTX_get_cert_store((WOLFSSL_CTX *)(ctx));
      add_ca_to_cert_store(st, x509);
      wolfSSL_X509_free(x509);
    }
    break;
  case COAP_PKI_KEY_PKCS11:
    /*// TODO: check if this can be implemented*/
    coap_log_err("PKCS11 Support not available in wolfSSL\n");
    return 0;
  default:
    coap_log_err("*** setup_pki: (D)TLS: Unknown key type %d\n",
                 setup_data->pki_key.key_type);
    return 0;
  }
  return 1;
}
#endif /* COAP_CLIENT_SUPPORT */

static char *
get_san_or_cn_from_cert(WOLFSSL_X509 *x509) {
  if (x509) {
    char *cn;
    int n;
    WOLF_STACK_OF(WOLFSSL_GENERAL_NAME) *san_list;
    char buffer[256];

    san_list = wolfSSL_X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (san_list) {
      int san_count = wolfSSL_sk_GENERAL_NAME_num(san_list);

      for (n = 0; n < san_count; n++) {
        const WOLFSSL_GENERAL_NAME *name = wolfSSL_sk_GENERAL_NAME_value(san_list, n);

        if (name->type == GEN_DNS) {
          const char *dns_name = (const char *)wolfSSL_ASN1_STRING_get0_data(name->d.dNSName);

          /* Make sure that there is not an embedded NUL in the dns_name */
          if (wolfSSL_ASN1_STRING_length(name->d.dNSName) != (int)strlen(dns_name))
            continue;
          cn = wolfSSL_strdup(dns_name);
          wolfSSL_sk_GENERAL_NAME_pop_free(san_list, wolfSSL_GENERAL_NAME_free);
          return cn;
        }
      }
      wolfSSL_sk_GENERAL_NAME_pop_free(san_list, wolfSSL_GENERAL_NAME_free);
    }
    /* Otherwise look for the CN= field */
    wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_subject_name((WOLFSSL_X509 *)(x509)), buffer,
                              sizeof(buffer));

    /* Need to emulate strcasestr() here.  Looking for CN= */
    n = (int)strlen(buffer) - 3;
    cn = buffer;
    while (n > 0) {
      if (((cn[0] == 'C') || (cn[0] == 'c')) &&
          ((cn[1] == 'N') || (cn[1] == 'n')) &&
          (cn[2] == '=')) {
        cn += 3;
        break;
      }
      cn++;
      n--;
    }
    if (n > 0) {
      char *ecn = strchr(cn, '/');
      if (ecn) {
        return wolfSSL_strndup(cn, ecn-cn);
      } else {
        return wolfSSL_strdup(cn);
      }
    }
  }
  return NULL;
}

static int
tls_verify_call_back(int preverify_ok, WOLFSSL_X509_STORE_CTX *ctx) {
  WOLFSSL *ssl = wolfSSL_X509_STORE_CTX_get_ex_data(ctx,
                                                    wolfSSL_get_ex_data_X509_STORE_CTX_idx());
  coap_session_t *session = wolfSSL_get_app_data(ssl);
  coap_wolfssl_context_t *context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_dtls_pki_t *setup_data = &context->setup_data;
  int depth = wolfSSL_X509_STORE_CTX_get_error_depth(ctx);
  int err = wolfSSL_X509_STORE_CTX_get_error(ctx);
  WOLFSSL_X509 *x509 = wolfSSL_X509_STORE_CTX_get_current_cert(ctx);
  char *cn = get_san_or_cn_from_cert(x509);
  int keep_preverify_ok = preverify_ok;

  if (!preverify_ok) {
    switch (err) {
    case WOLFSSL_X509_V_ERR_CERT_NOT_YET_VALID:
    case WOLFSSL_X509_V_ERR_CERT_HAS_EXPIRED:
      if (setup_data->allow_expired_certs)
        preverify_ok = 1;
      break;
    case WOLFSSL_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
      if (setup_data->allow_self_signed && !setup_data->check_common_ca)
        preverify_ok = 1;
      break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: /* Set if the CA is not known */
      if (!setup_data->verify_peer_cert)
        preverify_ok = 1;
      break;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
      if (setup_data->allow_no_crl)
        preverify_ok = 1;
      break;
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
      if (setup_data->allow_expired_crl)
        preverify_ok = 1;
      break;
    case WOLFSSL_X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case WOLFSSL_X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_AKID_SKID_MISMATCH:
      if (!setup_data->verify_peer_cert)
        preverify_ok = 1;
      break;
    default:
      break;
    }
    if (setup_data->cert_chain_validation &&
        depth > (setup_data->cert_chain_verify_depth + 1)) {
      preverify_ok = 0;
      err = WOLFSSL_X509_V_ERR_CERT_CHAIN_TOO_LONG;
      wolfSSL_X509_STORE_CTX_set_error(ctx, err);
    }
    if (!preverify_ok) {
      if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
        coap_log_warn("   %s: %s: '%s' depth=%d\n",
                      coap_session_str(session),
                      "Unknown CA", cn ? cn : "?", depth);
      } else {
        coap_log_warn("   %s: %s: '%s' depth=%d\n",
                      coap_session_str(session),
                      wolfSSL_X509_verify_cert_error_string(err), cn ? cn : "?", depth);
      }
    } else {
      coap_log_info("   %s: %s: overridden: '%s' depth=%d\n",
                    coap_session_str(session),
                    wolfSSL_X509_verify_cert_error_string(err), cn ? cn : "?", depth);
    }
  }
  /* Certificate - depth == 0 is the Client Cert */
  if (setup_data->validate_cn_call_back && keep_preverify_ok) {
    int length = wolfSSL_i2d_X509(x509, NULL);
    uint8_t *base_buf;
    uint8_t *base_buf2 = base_buf = wolfSSL_OPENSSL_malloc(length);

    /* base_buf2 gets moved to the end */
    wolfSSL_i2d_X509(x509, &base_buf2);
    if (!setup_data->validate_cn_call_back(cn, base_buf, length, session,
                                           depth, preverify_ok,
                                           setup_data->cn_call_back_arg)) {
      if (depth == 0) {
        wolfSSL_X509_STORE_CTX_set_error(ctx, WOLFSSL_X509_V_ERR_CERT_REJECTED);
      } else {
        wolfSSL_X509_STORE_CTX_set_error(ctx, WOLFSSL_X509_V_ERR_INVALID_CA);
      }
      preverify_ok = 0;
    }
    wolfSSL_OPENSSL_free(base_buf);
  }
  wolfSSL_OPENSSL_free(cn);
  return preverify_ok;
}

#if COAP_SERVER_SUPPORT
/*
 * During the SSL/TLS initial negotiations, tls_secret_call_back() is called so
 * it is possible to determine whether this is a PKI or PSK incoming
 * request and adjust the ciphers if necessary
 *
 * Set up by SSL_set_session_secret_cb() in tls_server_name_call_back()
 */
static int
tls_secret_call_back(WOLFSSL *ssl,
                     void *secret,
                     int *secretlen,
                     void *arg
                    ) {
  int     ii;
  int     psk_requested = 0;
  coap_session_t *session;
  coap_dtls_pki_t *setup_data = (coap_dtls_pki_t *)arg;

  session = (coap_session_t *)wolfSSL_get_app_data(ssl);
  assert(session != NULL);
  assert(session->context != NULL);
  WOLF_STACK_OF(WOLFSSL_CIPHER) *peer_ciphers = wolfSSL_get_ciphers_compat(
                                                    ssl);
  if (session == NULL ||
      session->context == NULL)
    return 0;

  if ((session->psk_key) ||
      (session->context->spsk_setup_data.psk_info.key.s &&
       session->context->spsk_setup_data.psk_info.key.length)) {
    /* Is PSK being requested - if so, we need to change algorithms */
    for (ii = 0; ii < wolfSSL_sk_SSL_CIPHER_num(peer_ciphers); ii++) {
      const WOLFSSL_CIPHER *peer_cipher = wolfSSL_sk_SSL_CIPHER_value(peer_ciphers, ii);

      coap_dtls_log(COAP_LOG_INFO, "Client cipher: %s\n",
                    wolfSSL_CIPHER_get_name(peer_cipher));
      if (strstr(wolfSSL_CIPHER_get_name(peer_cipher), "PSK")) {
        psk_requested = 1;
        break;
      }
    }
  }
  if (!psk_requested) {
    coap_log_debug("   %s: Using PKI ciphers\n",
                   coap_session_str(session));

    if (setup_data->verify_peer_cert) {
      wolfSSL_set_verify(ssl,
                         WOLFSSL_VERIFY_PEER |
                         WOLFSSL_VERIFY_CLIENT_ONCE |
                         WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         tls_verify_call_back);
    } else {
      wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, tls_verify_call_back);
    }

    /* Check CA Chain */
    if (setup_data->cert_chain_validation)
      wolfSSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth + 2);

    /* Certificate Revocation */
    if (setup_data->check_cert_revocation) {
      WOLFSSL_X509_VERIFY_PARAM *param;

      param = wolfSSL_X509_VERIFY_PARAM_new();
      wolfSSL_X509_VERIFY_PARAM_set_flags(param, WOLFSSL_CRL_CHECK);
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);
      /* TODO: we cannot set parameters at ssl level with wolfSSL, review*/
      //wolfSSL_set1_param(ssl, param);
      wolfSSL_CTX_set1_param(ctx, param);
      wolfSSL_X509_VERIFY_PARAM_free(param);
    }
    if (setup_data->additional_tls_setup_call_back) {
      /* Additional application setup wanted */
      if (!setup_data->additional_tls_setup_call_back(ssl, setup_data))
        return 0;
    }
  } else {
    if (session->psk_key) {
      memcpy(secret, session->psk_key->s, session->psk_key->length);
      *secretlen = session->psk_key->length;
    } else if (session->context->spsk_setup_data.psk_info.key.s &&
               session->context->spsk_setup_data.psk_info.key.length) {
      memcpy(secret, session->context->spsk_setup_data.psk_info.key.s,
             session->context->spsk_setup_data.psk_info.key.length);
      *secretlen = session->context->spsk_setup_data.psk_info.key.length;
    }
    coap_log_debug("   %s: Setting PSK ciphers\n",
                   coap_session_str(session));
    /*
     * Force a PSK algorithm to be used, so we do PSK
     */
    wolfSSL_set_cipher_list(ssl, COAP_WOLFSSL_PSK_CIPHERS);
    wolfSSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
  }
  return 0;
}

/*
 * During the SSL/TLS initial negotiations, tls_server_name_call_back() is
 * called so it is possible to set up an extra callback to determine whether
 * this is a PKI or PSK incoming request and adjust the ciphers if necessary
 *
 * Set up by SSL_CTX_set_tlsext_servername_callback() in
 * coap_dtls_context_set_pki()
 */
static int
tls_server_name_call_back(WOLFSSL *ssl,
                          int *sd COAP_UNUSED,
                          void *arg
                         ) {
  coap_dtls_pki_t *setup_data = (coap_dtls_pki_t *)arg;

  if (!ssl) {
    return noack_return;
  }

  if (setup_data->validate_sni_call_back) {
    /* SNI checking requested */
    coap_session_t *session = (coap_session_t *)wolfSSL_get_app_data(ssl);
    coap_wolfssl_context_t *context =
        ((coap_wolfssl_context_t *)session->context->dtls_context);
    const char *sni = wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME);
    size_t i;

    if (!sni || !sni[0]) {
      sni = "";
    }
    for (i = 0; i < context->sni_count; i++) {
      if (!strcasecmp(sni, context->sni_entry_list[i].sni)) {
        break;
      }
    }
    if (i == context->sni_count) {
      WOLFSSL_CTX *ctx;
      coap_dtls_pki_t sni_setup_data;
      coap_dtls_key_t *new_entry = setup_data->validate_sni_call_back(sni,
                                   setup_data->sni_call_back_arg);
      if (!new_entry) {
        return fatal_return;
      }
      /* Need to set up a new SSL_CTX to switch to */
      if (session->proto == COAP_PROTO_DTLS) {
        /* Set up DTLS context */
        ctx = wolfSSL_CTX_new(wolfDTLS_method());
        if (!ctx)
          goto error;
        wolfSSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        wolfSSL_CTX_set_app_data(ctx, &context->dtls);
        wolfSSL_CTX_set_read_ahead(ctx, 1);
        coap_set_user_prefs(ctx);
        wolfSSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_QUERY_MTU);
        //wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_COOKIE_EXCHANGE);
      }
#if !COAP_DISABLE_TCP
      else {
        /* Set up TLS context */
        ctx = wolfSSL_CTX_new(wolfSSLv23_method());
        if (!ctx)
          goto error;
        wolfSSL_CTX_set_app_data(ctx, &context->tls);
        wolfSSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        coap_set_user_prefs(ctx);
        wolfSSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        wolfSSL_CTX_set_alpn_select_cb(ctx, server_alpn_callback, NULL);
      }
#endif /* !COAP_DISABLE_TCP */
      sni_setup_data = *setup_data;
      sni_setup_data.pki_key = *new_entry;
      setup_pki_server(ctx, &sni_setup_data);

      context->sni_entry_list = wolfSSL_Realloc(context->sni_entry_list,
                                                (context->sni_count+1)*sizeof(sni_entry));
      context->sni_entry_list[context->sni_count].sni = wolfSSL_strdup(sni);
      context->sni_entry_list[context->sni_count].ctx = ctx;
      context->sni_count++;
    }
    wolfSSL_set_SSL_CTX(ssl, context->sni_entry_list[i].ctx);
    wolfSSL_clear_options(ssl, 0xFFFFFFFFL);
    wolfSSL_set_options(ssl, wolfSSL_CTX_get_options(context->sni_entry_list[i].ctx));
  }

  /*
   * Have to do extra call back next to get client algorithms
   * SSL_get_client_ciphers() does not work this early on
   */
  wolfSSL_set_session_secret_cb(ssl, tls_secret_call_back, arg);
  return SSL_TLSEXT_ERR_OK;

error:
  return warning_return;
}

/*
 * During the SSL/TLS initial negotiations, psk_tls_server_name_call_back() is
 * called to see if SNI is being used.
 *
 * Set up by SSL_CTX_set_tlsext_servername_callback()
 * in coap_dtls_context_set_spsk()
 */
static int
psk_tls_server_name_call_back(WOLFSSL *ssl,
                              int *sd COAP_UNUSED,
                              void *arg
                             ) {
  coap_dtls_spsk_t *setup_data = (coap_dtls_spsk_t *)arg;

  if (!ssl) {
    return noack_return;
  }

  if (setup_data->validate_sni_call_back) {
    /* SNI checking requested */
    coap_session_t *c_session = (coap_session_t *)wolfSSL_get_app_data(ssl);
    coap_wolfssl_context_t *o_context =
        ((coap_wolfssl_context_t *)c_session->context->dtls_context);
    const char *sni = wolfSSL_get_servername(ssl, WOLFSSL_SNI_HOST_NAME);
    size_t i;
    char lhint[COAP_DTLS_HINT_LENGTH];

    if (!sni || !sni[0]) {
      sni = "";
    }
    for (i = 0; i < o_context->psk_sni_count; i++) {
      if (!strcasecmp(sni, (char *)o_context->psk_sni_entry_list[i].sni)) {
        break;
      }
    }
    if (i == o_context->psk_sni_count) {
      WOLFSSL_CTX *ctx;
      const coap_dtls_spsk_info_t *new_entry =
          setup_data->validate_sni_call_back(sni,
                                             c_session,
                                             setup_data->sni_call_back_arg);
      if (!new_entry) {
        return fatal_return;
      }
      /* Need to set up a new SSL_CTX to switch to */
      if (c_session->proto == COAP_PROTO_DTLS) {
        /* Set up DTLS context */
        ctx = wolfSSL_CTX_new(wolfDTLS_method());
        if (!ctx)
          goto error;
        wolfSSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
        wolfSSL_CTX_set_app_data(ctx, &o_context->dtls);
        wolfSSL_CTX_set_read_ahead(ctx, 1);
        wolfSSL_CTX_set_cipher_list(ctx, COAP_WOLFSSL_CIPHERS);
        wolfSSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        wolfSSL_CTX_set_options(ctx, WOLFSSL_OP_NO_QUERY_MTU);
      }
#if !COAP_DISABLE_TCP
      else {
        /* Set up TLS context */
        ctx = wolfSSL_CTX_new(wolfSSLv23_method());
        if (!ctx)
          goto error;
        wolfSSL_CTX_set_app_data(ctx, &o_context->tls);
        wolfSSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
        wolfSSL_CTX_set_cipher_list(ctx, COAP_WOLFSSL_CIPHERS);
        wolfSSL_CTX_set_info_callback(ctx, coap_dtls_info_callback);
        wolfSSL_CTX_set_alpn_select_cb(ctx, server_alpn_callback, NULL);
      }
#endif /* !COAP_DISABLE_TCP */

      o_context->psk_sni_entry_list =
          wolfSSL_Realloc(o_context->psk_sni_entry_list,
                          (o_context->psk_sni_count+1)*sizeof(psk_sni_entry));
      o_context->psk_sni_entry_list[o_context->psk_sni_count].sni =
          wolfSSL_strdup(sni);
      o_context->psk_sni_entry_list[o_context->psk_sni_count].psk_info =
          *new_entry;
      o_context->psk_sni_entry_list[o_context->psk_sni_count].ctx =
          ctx;
      o_context->psk_sni_count++;
    }
    wolfSSL_set_SSL_CTX(ssl, o_context->psk_sni_entry_list[i].ctx);
    wolfSSL_clear_options(ssl, 0xFFFFFFFFL);
    wolfSSL_set_options(ssl,
                        wolfSSL_CTX_get_options(o_context->psk_sni_entry_list[i].ctx));
    coap_session_refresh_psk_key(c_session,
                                 &o_context->psk_sni_entry_list[i].psk_info.key);
    snprintf(lhint, sizeof(lhint), "%.*s",
             (int)o_context->psk_sni_entry_list[i].psk_info.hint.length,
             o_context->psk_sni_entry_list[i].psk_info.hint.s);
    wolfSSL_use_psk_identity_hint(ssl, lhint);
  }

  /*
   * Have to do extra call back next to get client algorithms
   * SSL_get_client_ciphers() does not work this early on
   */
  wolfSSL_set_session_secret_cb(ssl, tls_secret_call_back, arg);
  return SSL_TLSEXT_ERR_OK;

error:
  return warning_return;
}
#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_context_set_pki(coap_context_t *ctx,
                          const coap_dtls_pki_t *setup_data,
                          const coap_dtls_role_t role
                         ) {
  coap_wolfssl_context_t *context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);
  WOLFSSL_BIO *bio;
  if (!setup_data)
    return 0;
  context->setup_data = *setup_data;
  if (!context->setup_data.verify_peer_cert) {
    /* Needs to be clear so that no CA DNs are transmitted */
    context->setup_data.check_common_ca = 0;
    /* Allow all of these but warn if issue */
    context->setup_data.allow_self_signed = 1;
    context->setup_data.allow_expired_certs = 1;
    context->setup_data.cert_chain_validation = 1;
    context->setup_data.cert_chain_verify_depth = 10;
    context->setup_data.check_cert_revocation = 1;
    context->setup_data.allow_no_crl = 1;
    context->setup_data.allow_expired_crl = 1;
    context->setup_data.allow_bad_md_hash = 1;
    context->setup_data.allow_short_rsa_length = 1;
  }
#if COAP_SERVER_SUPPORT
  if (role == COAP_DTLS_ROLE_SERVER) {
    if (context->dtls.ctx) {
      if (!setup_pki_server(context->dtls.ctx, setup_data))
        return 0;

      wolfSSL_CTX_set_servername_arg(context->dtls.ctx, &context->setup_data);
      wolfSSL_CTX_set_tlsext_servername_callback(context->dtls.ctx, tls_server_name_call_back);
    }
#if !COAP_DISABLE_TCP
    if (context->tls.ctx) {
      if (!setup_pki_server(context->tls.ctx, setup_data))
        return 0;

      wolfSSL_CTX_set_servername_arg(context->tls.ctx, &context->setup_data);
      wolfSSL_CTX_set_tlsext_servername_callback(context->tls.ctx, tls_server_name_call_back);

      // For TLS only
      wolfSSL_CTX_set_alpn_select_cb(context->tls.ctx, server_alpn_callback, NULL);
    }
#endif /* !COAP_DISABLE_TCP */
  }
#else /* ! COAP_SERVER_SUPPORT */
  (void)role;
#endif /* ! COAP_SERVER_SUPPORT */

  if (!context->dtls.ssl) {
    /* This is set up to handle new incoming sessions to a server */
    context->dtls.ssl = wolfSSL_new(context->dtls.ctx);
    if (!context->dtls.ssl)
      return 0;
    bio = wolfSSL_BIO_new(context->dtls.meth);
    if (!bio) {
      wolfSSL_free(context->dtls.ssl);
      context->dtls.ssl = NULL;
      return 0;
    }
    wolfSSL_set_bio(context->dtls.ssl, bio, bio);
    wolfSSL_set_app_data(context->dtls.ssl, NULL);
    wolfSSL_set_options(context->dtls.ssl, WOLFSSL_OP_COOKIE_EXCHANGE);
    wolfSSL_dtls_set_mtu(context->dtls.ssl, COAP_DEFAULT_MTU);
  }
  context->psk_pki_enabled |= IS_PKI;
  return 1;
}

int
coap_dtls_context_set_pki_root_cas(coap_context_t *ctx,
                                   const char *ca_file,
                                   const char *ca_dir
                                  ) {
  coap_wolfssl_context_t *context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);
  if (context->dtls.ctx) {
    if (!wolfSSL_CTX_load_verify_locations(context->dtls.ctx, ca_file, ca_dir)) {
      coap_log_warn("Unable to install root CAs (%s/%s)\n",
                    ca_file ? ca_file : "NULL", ca_dir ? ca_dir : "NULL");
      return 0;
    }
  }
#if !COAP_DISABLE_TCP
  if (context->tls.ctx) {
    if (!wolfSSL_CTX_load_verify_locations(context->tls.ctx, ca_file, ca_dir)) {
      coap_log_warn("Unable to install root CAs (%s/%s)\n",
                    ca_file ? ca_file : "NULL", ca_dir ? ca_dir : "NULL");
      return 0;
    }
  }
#endif /* !COAP_DISABLE_TCP */
  return 1;
}

int
coap_dtls_context_check_keys_enabled(coap_context_t *ctx) {
  coap_wolfssl_context_t *context =
      ((coap_wolfssl_context_t *)ctx->dtls_context);
  return context->psk_pki_enabled ? 1 : 0;
}


void
coap_dtls_free_context(void *handle) {
  size_t i;
  coap_wolfssl_context_t *context = (coap_wolfssl_context_t *)handle;

  if (context->dtls.ssl)
    wolfSSL_free(context->dtls.ssl);
  if (context->dtls.ctx)
    wolfSSL_CTX_free(context->dtls.ctx);
  if (context->dtls.cookie_hmac)
    wolfSSL_HMAC_CTX_free(context->dtls.cookie_hmac);
  if (context->dtls.meth)
    wolfSSL_BIO_meth_free(context->dtls.meth);

#if !COAP_DISABLE_TCP
  if (context->tls.ctx)
    wolfSSL_CTX_free(context->tls.ctx);
  if (context->tls.meth)
    wolfSSL_BIO_meth_free(context->tls.meth);
#endif /* !COAP_DISABLE_TCP */
  for (i = 0; i < context->sni_count; i++) {
    wolfSSL_OPENSSL_free(context->sni_entry_list[i].sni);
  }
  if (context->sni_count)
    wolfSSL_OPENSSL_free(context->sni_entry_list);
  for (i = 0; i < context->psk_sni_count; i++) {
    wolfSSL_OPENSSL_free((char *)context->psk_sni_entry_list[i].sni);
  }
  if (context->psk_sni_count)
    wolfSSL_OPENSSL_free(context->psk_sni_entry_list);
  coap_free_type(COAP_STRING, context);
}

#if COAP_SERVER_SUPPORT
void *
coap_dtls_new_server_session(coap_session_t *session) {
  WOLFSSL_BIO *nbio = NULL;
  WOLFSSL *nssl = NULL, *ssl = NULL;
  coap_ssl_data *data;
  coap_dtls_context_t *dtls = &((coap_wolfssl_context_t *)session->context->dtls_context)->dtls;
  int r;
  const coap_bin_const_t *psk_hint;
  nssl = wolfSSL_new(dtls->ctx);
  if (!nssl) {
    // Remove bracket after removing debug
    goto error;
  }
  nbio = wolfSSL_BIO_new(dtls->meth);
  if (!nbio) {
    // Remove bracket after removing debug
    goto error;
  }
  wolfSSL_set_bio(nssl, nbio, nbio);
  wolfSSL_set_app_data(nssl, NULL);
  wolfSSL_set_options(nssl, WOLFSSL_OP_COOKIE_EXCHANGE);
  wolfSSL_dtls_set_mtu(nssl, (long)session->mtu);
  ssl = dtls->ssl;
  dtls->ssl = nssl;
  nssl = NULL;
  wolfSSL_set_app_data(ssl, session);
  data = (coap_ssl_data *)wolfSSL_BIO_get_data(wolfSSL_SSL_get_rbio(ssl));
  data->session = session;

  if (HRR_COOKIE) {
    if (wolfSSL_send_hrr_cookie(ssl, NULL, 0)
        != WOLFSSL_SUCCESS)
      coap_log_debug("Error: Unable to set cookie with Hello Retry Request\n");
  } else {
    wolfSSL_disable_hrr_cookie(ssl);
  }

#ifdef HAVE_SECURE_RENEGOTIATION
  if (USE_SECURE_RENEGOTIATION && wolfSSL_UseSecureRenegotiation(ssl) != WOLFSSL_SUCCESS) {
    coap_log_debug("Error: wolfSSL_UseSecureRenegotiation failed\n");
  }
#endif /* HAVE_SECURE_RENEGOTIATION */

  /* hint may get updated if/when handling SNI callback */
  psk_hint = coap_get_session_server_psk_hint(session);
  if (psk_hint != NULL && psk_hint->length) {
    char *hint = wolfSSL_OPENSSL_malloc(psk_hint->length + 1);

    if (hint) {
      memcpy(hint, psk_hint->s, psk_hint->length);
      hint[psk_hint->length] = '\000';
      wolfSSL_use_psk_identity_hint(ssl, hint);
      wolfSSL_OPENSSL_free(hint);
    } else {
      coap_log_warn("hint malloc failure\n");
    }
  }

#ifdef WOLFSSL_DTLS_CH_FRAG
#ifdef IS_DTLS13
  if (wolfSSL_dtls13_allow_ch_frag(ssl, 1) != WOLFSSL_SUCCESS) {
    coap_log_debug("Error: wolfSSL_dtls13_allow_ch_frag failed\n");
  }
#endif
#endif
  r = wolfSSL_accept(ssl);
  if (r == -1) {
    int err = wolfSSL_get_error(ssl, r);
    if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0) {
    wolfSSL_free(ssl);
    return NULL;
  }

  return ssl;

error:
  if (nssl)
    wolfSSL_free(nssl);
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_CLIENT_SUPPORT
static int
setup_client_ssl_session(coap_session_t *session, WOLFSSL *ssl
                        ) {
  coap_wolfssl_context_t *context =
      ((coap_wolfssl_context_t *)session->context->dtls_context);

  if (context->psk_pki_enabled & IS_PSK) {
    coap_dtls_cpsk_t *setup_data = &session->cpsk_setup_data;

    /* Issue SNI if requested */
    if (setup_data->client_sni &&
        wolfSSL_set_tlsext_host_name(ssl, setup_data->client_sni) != 1) {
      coap_log_warn("wolfSSL_set_tlsext_host_name: set '%s' failed",
                    setup_data->client_sni);
    }
    wolfSSL_set_psk_client_callback(ssl, coap_dtls_psk_client_callback);
#if COAP_SERVER_SUPPORT
    wolfSSL_set_psk_server_callback(ssl, coap_dtls_psk_server_callback);
#endif /* COAP_SERVER_SUPPORT */
    wolfSSL_set_cipher_list(ssl, COAP_WOLFSSL_PSK_CIPHERS);
    if (setup_data->validate_ih_call_back) {
      if (session->proto == COAP_PROTO_DTLS) {
        wolfSSL_set_max_proto_version(ssl,
                                      DTLS1_2_VERSION);
      }
#if !COAP_DISABLE_TCP
      else {
        wolfSSL_set_max_proto_version(ssl,
                                      TLS1_2_VERSION);
      }
#endif /* !COAP_DISABLE_TCP */
      coap_log_debug("CoAP Client restricted to (D)TLS1.2 with Identity Hint callback\n");
    }
  }
  if (context->psk_pki_enabled & IS_PKI) {
    coap_dtls_pki_t *setup_data = &context->setup_data;
    if (!setup_pki_ssl(ssl, setup_data, COAP_DTLS_ROLE_CLIENT))
      return 0;
    /* libcoap is managing (D)TLS connection based on setup_data options */
#if !COAP_DISABLE_TCP
    if (session->proto == COAP_PROTO_TLS)
      wolfSSL_set_alpn_protos(ssl, coap_alpn, sizeof(coap_alpn));
#endif /* !COAP_DISABLE_TCP */

    /* Issue SNI if requested */
    if (setup_data->client_sni &&
        wolfSSL_set_tlsext_host_name(ssl, setup_data->client_sni) != 1) {
      coap_log_warn("wolfSSL_set_tlsext_host_name: set '%s' failed",
                    setup_data->client_sni);
    }
    /* Certificate Revocation */
    if (setup_data->check_cert_revocation) {
      WOLFSSL_X509_VERIFY_PARAM *param;

      param = wolfSSL_X509_VERIFY_PARAM_new();
      wolfSSL_X509_VERIFY_PARAM_set_flags(param, WOLFSSL_CRL_CHECK);
      WOLFSSL_CTX *ctx = wolfSSL_get_SSL_CTX(ssl);
      /* TODO: we cannot set parameters at ssl level with wolfSSL, review*/
      wolfSSL_CTX_set1_param(ctx, param);
      wolfSSL_X509_VERIFY_PARAM_free(param);
    }
    /* Verify Peer */
    if (setup_data->verify_peer_cert)
      wolfSSL_set_verify(ssl,
                         WOLFSSL_VERIFY_PEER |
                         WOLFSSL_VERIFY_CLIENT_ONCE |
                         WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                         tls_verify_call_back);
    else
      wolfSSL_set_verify(ssl, WOLFSSL_VERIFY_NONE, tls_verify_call_back);

    /* Check CA Chain */
    if (setup_data->cert_chain_validation)
      wolfSSL_set_verify_depth(ssl, setup_data->cert_chain_verify_depth + 1);

  }
  return 1;
}

void *
coap_dtls_new_client_session(coap_session_t *session) {
  WOLFSSL_BIO *bio = NULL;
  WOLFSSL *ssl = NULL;
  coap_ssl_data *data;
  int r;
  coap_wolfssl_context_t *context = ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_dtls_context_t *dtls = &context->dtls;
  ssl = wolfSSL_new(dtls->ctx);
  if (!ssl) {
    // Remove bracket after removing debug
    goto error;
  }
  bio = wolfSSL_BIO_new(dtls->meth);
  if (!bio) {
    // Remove bracket after removing debug
    goto error;
  }
  data = (coap_ssl_data *)wolfSSL_BIO_get_data(bio);
  data->session = session;
  wolfSSL_set_bio(ssl, bio, bio);
  wolfSSL_set_app_data(ssl, session);
  wolfSSL_set_options(ssl, WOLFSSL_OP_COOKIE_EXCHANGE);
  wolfSSL_dtls_set_mtu(ssl, (long)session->mtu);

  if (!setup_client_ssl_session(session, ssl))
    goto error;

  session->dtls_timeout_count = 0;
  if (HRR_COOKIE) {
    wolfSSL_NoKeyShares(ssl);
  }
  r = wolfSSL_connect(ssl);
  if (r == -1) {
    int ret = wolfSSL_get_error(ssl, r);
    if (ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
  }

  if (r == 0)
    goto error;

  session->tls = ssl;
  return ssl;

error:
  if (ssl)
    wolfSSL_free(ssl);
  return NULL;
}

void
coap_dtls_session_update_mtu(coap_session_t *session) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  if (ssl)
    wolfSSL_dtls_set_mtu(ssl, (long)session->mtu); /* Instead of SSL_set_mtu */
}
#endif /* COAP_CLIENT_SUPPORT */

void
coap_dtls_free_session(coap_session_t *session) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  if (ssl) {
    if (!wolfSSL_SSL_in_init(ssl) && !(wolfSSL_get_shutdown(ssl) & WOLFSSL_SENT_SHUTDOWN)) {
      int r = wolfSSL_shutdown(ssl);
      if (r == 0)
        r = wolfSSL_shutdown(ssl);
    }
    wolfSSL_free(ssl);
    session->tls = NULL;
    if (session->context)
      coap_handle_event(session->context, COAP_EVENT_DTLS_CLOSED, session);
  }
}

ssize_t
coap_dtls_send(coap_session_t *session,
               const uint8_t *data, size_t data_len) {
  int r;
  WOLFSSL *ssl = (WOLFSSL *)session->tls;

  assert(ssl != NULL);

  session->dtls_event = -1;
  r = wolfSSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      r = 0;
    } else {
      coap_log_warn("coap_dtls_send: cannot send PDU\n");
      if (err == WOLFSSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  if (r > 0) {
    if (r == (ssize_t)data_len)
      coap_log_debug("*  %s: dtls:  sent %4d bytes\n",
                     coap_session_str(session), r);
    else
      coap_log_debug("*  %s: dtls:  sent %4d of %4zd bytes\n",
                     coap_session_str(session), r, data_len);
  }
  return r;
}

int
coap_dtls_is_context_timeout(void) {
  return 0;
}

coap_tick_t
coap_dtls_get_context_timeout(void *dtls_context) {
  (void)dtls_context;
  return 0;
}

coap_tick_t
coap_dtls_get_timeout(coap_session_t *session, coap_tick_t now COAP_UNUSED) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  coap_ssl_data *ssl_data;

  assert(ssl != NULL && session->state == COAP_SESSION_STATE_HANDSHAKE);
  ssl_data = (coap_ssl_data *)wolfSSL_BIO_get_data(wolfSSL_SSL_get_rbio(ssl));
  return ssl_data->timeout;
}

/*
 * return 1 timed out
 *        0 still timing out
 */
int
coap_dtls_handle_timeout(coap_session_t *session) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;

  assert(ssl != NULL && session->state == COAP_SESSION_STATE_HANDSHAKE);
  if ((++session->dtls_timeout_count > session->max_retransmit) ||
      (wolfSSL_DTLSv1_handle_timeout(ssl) < 0)) {
    /* Too many retries */
    coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
    return 1;
  }
  return 0;
}

#if COAP_SERVER_SUPPORT

int
coap_dtls_hello(coap_session_t *session,
                const uint8_t *data, size_t data_len) {
  coap_dtls_context_t *dtls = &((coap_wolfssl_context_t *)session->context->dtls_context)->dtls;
  coap_ssl_data *ssl_data;
  int r;
  static int counter = 0;
  counter++;
  wolfSSL_dtls_set_mtu(dtls->ssl, (long)session->mtu);
  ssl_data = (coap_ssl_data *)wolfSSL_BIO_get_data(wolfSSL_SSL_get_rbio(dtls->ssl));
  assert(ssl_data != NULL);

  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(session), ssl_data->pdu_len);
  }

  ssl_data->session = session;
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;
  r=1;

  return r;
}

#endif /* COAP_SERVER_SUPPORT */

int
coap_dtls_receive(coap_session_t *session, const uint8_t *data, size_t data_len) {
  coap_ssl_data *ssl_data;
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  int r;

  assert(ssl != NULL);

  int in_init = wolfSSL_SSL_in_init(ssl);
  uint8_t pdu[COAP_RXBUFFER_SIZE];
  ssl_data = (coap_ssl_data *)wolfSSL_BIO_get_data(wolfSSL_SSL_get_rbio(ssl));
  assert(ssl_data != NULL);

  if (ssl_data->pdu_len) {
    coap_log_err("** %s: Previous data not read %u bytes\n",
                 coap_session_str(session), ssl_data->pdu_len);
  }
  ssl_data->pdu = data;
  ssl_data->pdu_len = (unsigned)data_len;

  session->dtls_event = -1;
  r = wolfSSL_read(ssl, pdu, (int)sizeof(pdu));
  if (r > 0) {
    r =  coap_handle_dgram(session->context, session, pdu, (size_t)r);
    goto finished;
  } else {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      r = 0;
    } else {
      if (err == WOLFSSL_ERROR_ZERO_RETURN)        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
    if (session->dtls_event >= 0) {
      /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected() */
      if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
        coap_handle_event(session->context, session->dtls_event, session);
      if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
          session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
        coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
        ssl_data = NULL;
        r = -1;
      }
    }
  }

finished:
  if (ssl_data && ssl_data->pdu_len) {
    /* pdu data is held on stack which will not stay there */
    coap_log_debug("coap_dtls_receive: ret %d: remaining data %u\n", r, ssl_data->pdu_len);
    ssl_data->pdu_len = 0;
    ssl_data->pdu = NULL;
  }
  if (r > 0) {
    coap_log_debug("*  %s: dtls:  recv %4d bytes\n",
                   coap_session_str(session), r);
  }
  return r;
}

unsigned int
coap_dtls_get_overhead(coap_session_t *session) {
  unsigned int overhead = 37;
  const WOLFSSL_CIPHER *s_ciph = NULL;
  if (session->tls != NULL)
    s_ciph = wolfSSL_get_current_cipher(session->tls);
  if (s_ciph) {
    unsigned int ivlen, maclen, blocksize = 1, pad = 0;

    const WOLFSSL_EVP_CIPHER *e_ciph;
    const WOLFSSL_EVP_MD *e_md;
    char cipher[128];

    e_ciph = wolfSSL_EVP_get_cipherbynid(wolfSSL_CIPHER_get_cipher_nid(s_ciph));

    switch (WOLFSSL_EVP_CIPHER_mode(e_ciph)) {

    case WOLFSSL_EVP_CIPH_GCM_MODE:
      ivlen = WOLFSSL_EVP_GCM_TLS_EXPLICIT_IV_LEN;
      maclen = WOLFSSL_EVP_GCM_TLS_TAG_LEN;
      break;

    case WOLFSSL_EVP_CIPH_CCM_MODE:
      ivlen = WOLFSSL_EVP_CCM_TLS_EXPLICIT_IV_LEN;
      wolfSSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      if (strstr(cipher, "CCM8"))
        maclen = 8;
      else
        maclen = 16;
      break;

    case WOLFSSL_EVP_CIPH_CBC_MODE:
      e_md = wolfSSL_EVP_get_digestbynid(wolfSSL_CIPHER_get_digest_nid(s_ciph));
      blocksize = wolfSSL_EVP_CIPHER_block_size(e_ciph);
      ivlen = wolfSSL_EVP_CIPHER_iv_length(e_ciph);
      pad = 1;
      maclen = wolfSSL_EVP_MD_size(e_md);
      break;

    case WOLFSSL_EVP_CIPH_STREAM_CIPHER:
      /* Seen with PSK-CHACHA20-POLY1305 */
      ivlen = 8;
      maclen = 8;
      break;

    default:
      wolfSSL_CIPHER_description(s_ciph, cipher, sizeof(cipher));
      coap_log_warn("Unknown overhead for DTLS with cipher %s\n",
                    cipher);
      ivlen = 8;
      maclen = 16;
      break;
    }
    overhead = WOLFSSL_DTLS13_RT_HEADER_LENGTH + ivlen + maclen + blocksize - 1 +
               pad;
  }
  return overhead;
}

#if !COAP_DISABLE_TCP
#if COAP_CLIENT_SUPPORT
void *
coap_tls_new_client_session(coap_session_t *session) {
  WOLFSSL_BIO *bio = NULL;
  WOLFSSL *ssl = NULL;
  int r;
  coap_wolfssl_context_t *context = ((coap_wolfssl_context_t *)session->context->dtls_context);
  coap_tls_context_t *tls = &context->tls;

  ssl = wolfSSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = wolfSSL_BIO_new(tls->meth);
  if (!bio)
    goto error;
  wolfSSL_BIO_set_data(bio, session);
  wolfSSL_set_bio(ssl, bio, bio);
  wolfSSL_set_app_data(ssl, session);

  if (!setup_client_ssl_session(session, ssl))
    return 0;

  r = wolfSSL_connect(ssl);
  if (r == -1) {
    int ret = wolfSSL_get_error(ssl, r);
    if (ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE)
      r = 0;
    if (ret == WOLFSSL_ERROR_WANT_READ)
      session->sock.flags |= COAP_SOCKET_WANT_READ;
    if (ret == WOLFSSL_ERROR_WANT_WRITE) {
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
      coap_epoll_ctl_mod(&session->sock,
                         EPOLLOUT |
                         ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                          EPOLLIN : 0),
                         __func__);
#endif /* COAP_EPOLL_SUPPORT */
    }
  }

  if (r == 0)
    goto error;

  session->tls = ssl;
  if (wolfSSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  return ssl;

error:
  if (ssl)
    wolfSSL_free(ssl);
  return NULL;
}
#endif /* COAP_CLIENT_SUPPORT */

#if COAP_SERVER_SUPPORT
void *
coap_tls_new_server_session(coap_session_t *session) {
  WOLFSSL_BIO *bio = NULL;
  WOLFSSL *ssl = NULL;
  coap_tls_context_t *tls = &((coap_wolfssl_context_t *)session->context->dtls_context)->tls;
  int r;
  const coap_bin_const_t *psk_hint;

  ssl = wolfSSL_new(tls->ctx);
  if (!ssl)
    goto error;
  bio = wolfSSL_BIO_new(tls->meth);
  if (!bio)
    goto error;
  wolfSSL_BIO_set_data(bio, session);
  wolfSSL_set_bio(ssl, bio, bio);
  wolfSSL_set_app_data(ssl, session);


  psk_hint = coap_get_session_server_psk_hint(session);
  if (psk_hint != NULL && psk_hint->length) {
    char *hint = wolfSSL_OPENSSL_malloc(psk_hint->length + 1);

    if (hint) {
      memcpy(hint, psk_hint->s, psk_hint->length);
      hint[psk_hint->length] = '\000';
      wolfSSL_use_psk_identity_hint(ssl, hint);
      wolfSSL_OPENSSL_free(hint);
    } else {
      coap_log_warn("hint malloc failure\n");
    }
  }

  r = wolfSSL_accept(ssl);
  if (r == -1) {
    int err = wolfSSL_get_error(ssl, r);
    if (err != WOLFSSL_ERROR_WANT_READ && err != WOLFSSL_ERROR_WANT_WRITE) {
      r = 0;
      // Remove brackets after removing debug
    }
    if (err == WOLFSSL_ERROR_WANT_READ) {
      session->sock.flags |= COAP_SOCKET_WANT_READ;
      // Remove brackets after removing debug
    }
    if (err == WOLFSSL_ERROR_WANT_WRITE) {
      session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
      coap_epoll_ctl_mod(&session->sock,
                         EPOLLOUT |
                         ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                          EPOLLIN : 0),
                         __func__);
#endif /* COAP_EPOLL_SUPPORT */
    }
  }

  if (r == 0)
    goto error;

  session->tls = ssl;
  if (wolfSSL_is_init_finished(ssl)) {
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  return ssl;

error:
  if (ssl)
    wolfSSL_free(ssl);
  return NULL;
}
#endif /* COAP_SERVER_SUPPORT */

void
coap_tls_free_session(coap_session_t *session) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  if (ssl) {
    if (!wolfSSL_SSL_in_init(ssl) && !(wolfSSL_get_shutdown(ssl) & WOLFSSL_SENT_SHUTDOWN)) {
      int r = wolfSSL_shutdown(ssl);
      if (r == 0)
        r = wolfSSL_shutdown(ssl);
    }
    wolfSSL_free(ssl);
    session->tls = NULL;
    if (session->context)
      coap_handle_event(session->context, COAP_EVENT_DTLS_CLOSED, session);
  }
}

/*
 * strm
 * return +ve Number of bytes written.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_write(coap_session_t *session, const uint8_t *data, size_t data_len) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  int r, in_init;

  if (ssl == NULL)
    return -1;

  in_init = !wolfSSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = wolfSSL_write(ssl, data, (int)data_len);

  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      if (err == WOLFSSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      else if (err == WOLFSSL_ERROR_WANT_WRITE) {
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
        coap_epoll_ctl_mod(&session->sock,
                           EPOLLOUT |
                           ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                            EPOLLIN : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
      }
      r = 0;
    } else {
      coap_log_info("***%s: coap_tls_write: cannot send PDU\n",
                    coap_session_str(session));
      if (err == WOLFSSL_ERROR_ZERO_RETURN)
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && wolfSSL_is_init_finished(ssl)) {
    coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                  coap_session_str(session), wolfSSL_get_cipher((ssl)));
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  if (r >= 0) {
    if (r == (ssize_t)data_len)
      coap_log_debug("*  %s: tls:   sent %4d bytes\n",
                     coap_session_str(session), r);
    else
      coap_log_debug("*  %s: tls:   sent %4d of %4zd bytes\n",
                     coap_session_str(session), r, data_len);
  }
  return r;
}

/*
 * strm
 * return >=0 Number of bytes read.
 *         -1 Error (error in errno).
 */
ssize_t
coap_tls_read(coap_session_t *session, uint8_t *data, size_t data_len) {
  WOLFSSL *ssl = (WOLFSSL *)session->tls;
  int r, in_init;

  if (ssl == NULL) {
    errno = ENXIO;
    return -1;
  }

  in_init = !wolfSSL_is_init_finished(ssl);
  session->dtls_event = -1;
  r = wolfSSL_read(ssl, data, (int)data_len);
  if (r <= 0) {
    int err = wolfSSL_get_error(ssl, r);
    if (err == WOLFSSL_ERROR_WANT_READ || err == WOLFSSL_ERROR_WANT_WRITE) {
      if (in_init && wolfSSL_is_init_finished(ssl)) {
        coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                      coap_session_str(session), wolfSSL_get_cipher((ssl)));
        coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
        session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
      }
      if (err == WOLFSSL_ERROR_WANT_READ)
        session->sock.flags |= COAP_SOCKET_WANT_READ;
      if (err == WOLFSSL_ERROR_WANT_WRITE) {
        session->sock.flags |= COAP_SOCKET_WANT_WRITE;
#ifdef COAP_EPOLL_SUPPORT
        coap_epoll_ctl_mod(&session->sock,
                           EPOLLOUT |
                           ((session->sock.flags & COAP_SOCKET_WANT_READ) ?
                            EPOLLIN : 0),
                           __func__);
#endif /* COAP_EPOLL_SUPPORT */
      }
      r = 0;
    } else {
      if (err == WOLFSSL_ERROR_ZERO_RETURN)        /* Got a close notify alert from the remote side */
        session->dtls_event = COAP_EVENT_DTLS_CLOSED;
      else if (err == WOLFSSL_ERROR_SSL)
        session->dtls_event = COAP_EVENT_DTLS_ERROR;
      r = -1;
    }
  } else if (in_init && wolfSSL_is_init_finished(ssl)) {
    coap_dtls_log(COAP_LOG_INFO, "*  %s: Using cipher: %s\n",
                  coap_session_str(session), wolfSSL_get_cipher((ssl)));
    coap_handle_event(session->context, COAP_EVENT_DTLS_CONNECTED, session);
    session->sock.lfunc[COAP_LAYER_TLS].l_establish(session);
  }

  if (session->dtls_event >= 0) {
    /* COAP_EVENT_DTLS_CLOSED event reported in coap_session_disconnected() */
    if (session->dtls_event != COAP_EVENT_DTLS_CLOSED)
      coap_handle_event(session->context, session->dtls_event, session);
    if (session->dtls_event == COAP_EVENT_DTLS_ERROR ||
        session->dtls_event == COAP_EVENT_DTLS_CLOSED) {
      coap_session_disconnected(session, COAP_NACK_TLS_FAILED);
      r = -1;
    }
  }

  if (r > 0) {
    coap_log_debug("*  %s: tls:   recv %4d bytes\n",
                   coap_session_str(session), r);
  }
  return r;
}
#endif /* !COAP_DISABLE_TCP */

#if COAP_SERVER_SUPPORT
coap_digest_ctx_t *
coap_digest_setup(void) {
  WOLFSSL_EVP_MD_CTX *digest_ctx = wolfSSL_EVP_MD_CTX_new();

  if (digest_ctx) {
    wolfSSL_EVP_DigestInit_ex(digest_ctx, wolfSSL_EVP_sha256(), NULL);
  }
  return digest_ctx;
}

void
coap_digest_free(coap_digest_ctx_t *digest_ctx) {
  wolfSSL_EVP_MD_CTX_free(digest_ctx);
}

int
coap_digest_update(coap_digest_ctx_t *digest_ctx,
                   const uint8_t *data,
                   size_t data_len) {
  return wolfSSL_EVP_DigestUpdate(digest_ctx, data, data_len);
}

int
coap_digest_final(coap_digest_ctx_t *digest_ctx,
                  coap_digest_t *digest_buffer) {
  unsigned int size = sizeof(coap_digest_t);
  int ret = wolfSSL_EVP_DigestFinal_ex(digest_ctx, (uint8_t *)digest_buffer, &size);

  coap_digest_free(digest_ctx);
  return ret;
}
#endif /* COAP_SERVER_SUPPORT */

#if COAP_WS_SUPPORT || COAP_OSCORE_SUPPORT
static void
coap_crypto_output_errors(const char *prefix) {
#if COAP_MAX_LOGGING_LEVEL < _COAP_LOG_WARN
  (void)prefix;
#else /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_WARN */
  unsigned long e;

  while ((e = wolfSSL_ERR_get_error()))
    coap_log_warn("%s: %s%s\n",
                  prefix,
                  wolfSSL_ERR_reason_error_string(e),
                  ssl_function_definition(e));
#endif /* COAP_MAX_LOGGING_LEVEL >= _COAP_LOG_WARN */
}
#endif /* COAP_WS_SUPPORT || COAP_OSCORE_SUPPORT */

#if COAP_WS_SUPPORT
/*
 * The struct hash_algs and the function get_hash_alg() are used to
 * determine which hash type to use for creating the required hash object.
 */
static struct hash_algs {
  cose_alg_t alg;
  const WOLFSSL_EVP_MD *(*get_hash)(void);
  size_t length; /* in bytes */
} hashs[] = {
  {COSE_ALGORITHM_SHA_1, wolfSSL_EVP_sha1, 20},
  {COSE_ALGORITHM_SHA_256_64, wolfSSL_EVP_sha256, 8},
  {COSE_ALGORITHM_SHA_256_256, wolfSSL_EVP_sha256, 32},
  {COSE_ALGORITHM_SHA_512, wolfSSL_EVP_sha512, 64},
};

static const WOLFSSL_EVP_MD *
get_hash_alg(cose_alg_t alg, size_t *length) {
  size_t idx;

  for (idx = 0; idx < sizeof(hashs) / sizeof(struct hash_algs); idx++) {
    if (hashs[idx].alg == alg) {
      *length = hashs[idx].length;
      return hashs[idx].get_hash();
    }
  }
  coap_log_debug("get_hash_alg: COSE hash %d not supported\n", alg);
  return NULL;
}

int
coap_crypto_hash(cose_alg_t alg,
                 const coap_bin_const_t *data,
                 coap_bin_const_t **hash) {
  unsigned int length;
  const WOLFSSL_EVP_MD *evp_md;
  WOLFSSL_EVP_MD_CTX *evp_ctx = NULL;
  coap_binary_t *dummy = NULL;
  size_t hash_length;

  if ((evp_md = get_hash_alg(alg, &hash_length)) == NULL) {
    coap_log_debug("coap_crypto_hash: algorithm %d not supported\n", alg);
    return 0;
  }
  evp_ctx = wolfSSL_EVP_MD_CTX_new();
  if (evp_ctx == NULL)
    goto error;
  if (wolfSSL_EVP_DigestInit_ex(evp_ctx, evp_md, NULL) == 0)
    goto error;
  ;
  if (wolfSSL_EVP_DigestUpdate(evp_ctx, data->s, data->length) == 0)
    goto error;
  ;
  dummy = coap_new_binary(EVP_MAX_MD_SIZE);
  if (dummy == NULL)
    goto error;
  if (wolfSSL_EVP_DigestFinal_ex(evp_ctx, dummy->s, &length) == 0)
    goto error;
  dummy->length = length;
  if (hash_length < dummy->length)
    dummy->length = hash_length;
  *hash = (coap_bin_const_t *)(dummy);
  wolfSSL_EVP_MD_CTX_free(evp_ctx);
  return 1;

error:
  coap_crypto_output_errors("coap_crypto_hash");
  coap_delete_binary(dummy);
  if (evp_ctx)
    wolfSSL_EVP_MD_CTX_free(evp_ctx);
  return 0;
}
#endif /* COAP_WS_SUPPORT */

#if COAP_OSCORE_SUPPORT
int
coap_oscore_is_supported(void) {
  return 1;
}

/*
 * The struct cipher_algs and the function get_cipher_alg() are used to
 * determine which cipher type to use for creating the required cipher
 * suite object.
 */
static struct cipher_algs {
  cose_alg_t alg;
  const WOLFSSL_EVP_CIPHER *(*get_cipher)(void);
} ciphers[] = {{COSE_ALGORITHM_AES_CCM_16_64_128, wolfSSL_EVP_aes_128_ccm},
  {COSE_ALGORITHM_AES_CCM_16_64_256, wolfSSL_EVP_aes_256_ccm}
};

static const WOLFSSL_EVP_CIPHER *
get_cipher_alg(cose_alg_t alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(ciphers) / sizeof(struct cipher_algs); idx++) {
    if (ciphers[idx].alg == alg)
      return ciphers[idx].get_cipher();
  }
  coap_log_debug("get_cipher_alg: COSE cipher %d not supported\n", alg);
  return NULL;
}

/*
 * The struct hmac_algs and the function get_hmac_alg() are used to
 * determine which hmac type to use for creating the required hmac
 * suite object.
 */
static struct hmac_algs {
  cose_hmac_alg_t hmac_alg;
  const WOLFSSL_EVP_MD *(*get_hmac)(void);
} hmacs[] = {
  {COSE_HMAC_ALG_HMAC256_256, wolfSSL_EVP_sha256},
  {COSE_HMAC_ALG_HMAC384_384, wolfSSL_EVP_sha384},
  {COSE_HMAC_ALG_HMAC512_512, wolfSSL_EVP_sha512},
};

static const WOLFSSL_EVP_MD *
get_hmac_alg(cose_hmac_alg_t hmac_alg) {
  size_t idx;

  for (idx = 0; idx < sizeof(hmacs) / sizeof(struct hmac_algs); idx++) {
    if (hmacs[idx].hmac_alg == hmac_alg)
      return hmacs[idx].get_hmac();
  }
  coap_log_debug("get_hmac_alg: COSE HMAC %d not supported\n", hmac_alg);
  return NULL;
}

int
coap_crypto_check_cipher_alg(cose_alg_t alg) {
  return get_cipher_alg(alg) != NULL;
}

int
coap_crypto_check_hkdf_alg(cose_hkdf_alg_t hkdf_alg) {
  cose_hmac_alg_t hmac_alg;

  if (!cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg))
    return 0;
  return get_hmac_alg(hmac_alg) != NULL;
}

#define C(Func)                                                                \
  if (1 != (Func)) {                                                           \
    goto error;                                                                \
  }

int
coap_crypto_aead_encrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {

  Aes aes;
  int ret;
  int result_len;
  int nonce_length;
  byte *authTag = NULL;

  if (data == NULL)
    return 0;

  assert(params != NULL);
  if (!params)
    return 0;

  const coap_crypto_aes_ccm_t *ccm = &params->params.aes;

  if (ccm->key.s == NULL || ccm->nonce == NULL)
    goto error;

  result_len = data->length;
  nonce_length = 15 - ccm->l;

  ret = wc_AesCcmSetKey(&aes, ccm->key.s, ccm->key.length);
  if (ret != 0)
    goto error;

  //byte authTag[ccm->tag_len];
  authTag = (byte *)malloc(ccm->tag_len * sizeof(byte));
  if (!authTag) {
    free(authTag);
    goto error;
  }
  ret = wc_AesCcmEncrypt(&aes, result, data->s, data->length, ccm->nonce,
                         nonce_length, authTag, ccm->tag_len,
                         aad->s, aad->length);

  if (ret != 0)
    goto error;

  memcpy(result + result_len, authTag, ccm->tag_len);
  result_len += sizeof(authTag);
  *max_result_len = result_len;

  return 1;
error:
  coap_crypto_output_errors("coap_crypto_aead_encrypt");
  return 0;
}


int
coap_crypto_aead_decrypt(const coap_crypto_param_t *params,
                         coap_bin_const_t *data,
                         coap_bin_const_t *aad,
                         uint8_t *result,
                         size_t *max_result_len) {

  Aes aes;
  int ret;
  int len;

  if (data == NULL)
    return 0;

  if (data == NULL)
    return 0;

  assert(params != NULL);
  if (!params)
    return 0;

  const coap_crypto_aes_ccm_t *ccm = &params->params.aes;
  byte authTag[ccm->tag_len];

  if (data->length < ccm->tag_len) {
    return 0;
  } else {
    memcpy(authTag, data->s + data->length - ccm->tag_len, sizeof(authTag));
    data->length -= ccm->tag_len;
  }

  if (ccm->key.s == NULL || ccm->nonce == NULL)
    goto error;

  ret = wc_AesCcmSetKey(&aes, ccm->key.s, ccm->key.length);
  if (ret != 0)
    goto error;

  len = data->length;

  ret = wc_AesCcmDecrypt(&aes, result, data->s, len, ccm->nonce,
                         15 - ccm->l, authTag, sizeof(authTag),
                         aad->s, aad->length);

  if (ret != 0)
    goto error;

  *max_result_len = len;

  return 1;
error:
  coap_crypto_output_errors("coap_crypto_aead_decrypt");
  return 0;
}

int
coap_crypto_hmac(cose_hmac_alg_t hmac_alg,
                 coap_bin_const_t *key,
                 coap_bin_const_t *data,
                 coap_bin_const_t **hmac) {
  unsigned int result_len;
  const WOLFSSL_EVP_MD *evp_md;
  coap_binary_t *dummy = NULL;

  assert(key);
  assert(data);
  assert(hmac);

  if ((evp_md = get_hmac_alg(hmac_alg)) == 0) {
    coap_log_debug("coap_crypto_hmac: algorithm %d not supported\n", hmac_alg);
    return 0;
  }
  dummy = coap_new_binary(EVP_MAX_MD_SIZE);
  if (dummy == NULL)
    return 0;
  result_len = (unsigned int)dummy->length;
  if (wolfSSL_HMAC((evp_md),
                   (key->s),
                   ((int)key->length),
                   (data->s),
                   ((int)data->length),
                   (dummy->s),
                   (&result_len))) {
    dummy->length = result_len;
    *hmac = (coap_bin_const_t *)dummy;
    return 1;
  }

  coap_crypto_output_errors("coap_crypto_hmac");
  return 0;
}

#endif /* COAP_OSCORE_SUPPORT */

#else /* !COAP_WITH_LIBWOLFSSL */

#ifdef __clang__
/* Make compilers happy that do not like empty modules. As this function is
 * never used, we ignore -Wunused-function at the end of compiling this file
 */
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
static inline void
dummy(void) {
}

#endif /* COAP_WITH_LIBWOLFSSL */
